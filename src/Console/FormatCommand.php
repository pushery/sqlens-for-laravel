<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
use Illuminate\Filesystem\Filesystem;
use Pushery\SQLens\Capture\MigrationPaths;
use Pushery\SQLens\Format\BackendDegradation;
use Pushery\SQLens\Format\Dialect;
use Pushery\SQLens\Format\DialectResolver;
use Pushery\SQLens\Format\FormatConfig;
use Pushery\SQLens\Format\FormatDiscovery;
use Pushery\SQLens\Format\FormatResult;
use Pushery\SQLens\Format\FormatterRegistry;
use Pushery\SQLens\Format\FormatUndeterminedReason;
use Pushery\SQLens\Format\SafeFileWriter;
use Pushery\SQLens\Format\SqlFileScanner;
use Pushery\SQLens\Format\UnifiedDiff;
use Pushery\SQLens\PackageVersion;
use Pushery\SQLens\Reporting\Github\GithubReporter;
use Pushery\SQLens\Reporting\Github\WorkflowCommandEscaping;
use Symfony\Component\Console\Output\ConsoleOutputInterface;

/**
 * One house style for the SQL in a repository — and, with `--check`, the question a CI step asks.
 *
 * ## `--check` is not a dry run, it is a different question
 *
 * A dry run says what WOULD happen. `--check` answers whether anything would, and exits non-zero
 * when the answer is yes. The distinction matters because the second is what a pipeline can act on:
 * it needs a verdict, not a report to read.
 *
 * ## It writes through `SafeFileWriter`, never `file_put_contents`
 *
 * That adapter's docblock has the reasons, and both are about destroying work: a truncated write on
 * an interrupted run, and an unnecessary write that restarts every watcher over an empty diff.
 *
 * ## A file it cannot format is REPORTED, never skipped
 *
 * A formatter that quietly passed over what it could not parse would report a clean tree while
 * leaving the one file somebody needs to look at untouched — and `--check` would call that repository
 * formatted. Every undetermined result is named, with its reason, and it moves the exit code.
 *
 * ## `sqlens:format --format=json` reads twice, and that is the deliberate choice
 *
 * The suite is called `format` and so is the option. `--reporter=` would read better here and would
 * make this the one command in the package whose report format is requested differently from the
 * other seven — a grammar somebody has to remember per command. Consistency beats elegance, so the
 * collision stays and is named here rather than discovered.
 *
 * ## The report does NOT go through the shared Result model, and that is a decision
 *
 * `console`, `json` and `github` are this command's own narrow set, resolved here rather than
 * through `ReporterManager`. Not a shortcut around the reporter contract — a measurement of it. A
 * `Finding` requires a rule id, a category, a LEVEL, a documentation URL and a `SubjectContext`; a
 * `RunContext` requires server versions, a capture mode and an active-rule count. A format run has
 * none of those: it applies no rules, reads no database, and this command's own specification says
 * format uses no levels. Routing it through anyway means minting rule ids for "this file would be
 * reformatted" and reporting `hidden-rules=0` on a run that withheld nothing because it had nothing
 * to withhold — a reader is then told two things that are not true so that a transport can be
 * reused. `sqlens:doctor` reached the same conclusion for the same reason and holds its own pair.
 *
 * What IS shared is everything that can be: the misconfiguration rule for an unknown format, the
 * exit-code vocabulary, and the workflow-command escaping ({@see WorkflowCommandEscaping}).
 */
final class FormatCommand extends Command
{
    use ResolvesStrictTools;

    /**
     * The formats this command answers to — its own set, deliberately narrower than the registry's.
     *
     * `sarif` and `agent` are absent because they describe findings, and this command produces
     * none. Accepting a format it cannot honestly produce is the same defect as hiding one it can.
     *
     * @var list<string>
     */
    private const array FORMATS = ['console', 'json', 'github'];

    /**
     * GitHub displays at most ten annotations per level per run and drops the rest without saying so.
     *
     * A repository with two hundred unformatted files would therefore get ten annotations and a
     * green-looking absence of the other hundred and ninety. One slot is kept for the line that says
     * how many were withheld — the same arithmetic
     * {@see GithubReporter} uses, for the same reason.
     */
    private const int ANNOTATION_LIMIT = 10;

    /** @var string */
    protected $signature = 'sqlens:format
        {path?* : A path to format; repeatable. The same thing as --path=, in the form an editor or a pre-commit hook passes}
        {--path=* : A path to format; repeatable. Defaults to the application\'s registered migration paths}
        {--format=console : The report format — console, json or github. Yes, `--format` on `sqlens:format`; see the class docblock}
        {--check : Report whether anything WOULD be reformatted and exit non-zero if so, changing nothing}
        {--diff : Print a unified diff of what WOULD change and write nothing. Informational: it does not set the exit code — combine with --check for that}
        {--strict-tools : Treat a backend this run could not use as an error, not a degradation (overrides the configured strict_tools)}
        {--no-strict-tools : Treat a backend this run could not use as a degradation (overrides the configured strict_tools)}
        {--backend= : auto, php, pgformatter or sqlfluff. Overrides the configured backend}
        {--dialect= : auto, pgsql or mysql. Overrides the configured dialect}';

    /** @var string */
    protected $description = 'Format the SQL in your migrations to one house style, or check that it already is.';

    public function handle(Repository $config, FormatterRegistry $formatters, DialectResolver $dialects, MigrationPaths $paths, Filesystem $filesystem): int
    {
        // BEFORE anything is resolved, scanned or written. A typo in `--format` must not first
        // rewrite two hundred files and then complain about the option it was told at the start —
        // the same placement rule the strict-backend refusal below follows, for the same reason.
        //
        // And it is a refusal, never a quiet fall back to console: a pipeline handed console text
        // where it asked for a machine format fails somewhere else entirely, with nothing pointing
        // back here.
        $format = $this->option('format');

        if (! is_string($format) || ! in_array($format, self::FORMATS, true)) {
            $this->report(sprintf(
                'Unknown report format "%s". Available formats: %s.',
                is_scalar($format) ? (string) $format : get_debug_type($format),
                implode(', ', self::FORMATS),
            ));

            return ExitCode::Misconfiguration->value;
        }

        $settings = FormatConfig::from($config);
        $backend = is_string($named = $this->option('backend')) && $named !== '' ? $named : $settings->backend;

        $requested = is_string($flag = $this->option('dialect')) && $flag !== '' ? $flag : $settings->dialect;
        $resolved = $dialects->resolve($requested);

        // ⚠️ An unresolved dialect is NOT a refusal. `sqlens:format` with no database at all is the
        // north-star this suite is built around — a formatter that needed a connection to reformat a
        // text file would be unusable in exactly the setting it is most useful in: a fresh checkout,
        // a pre-commit hook, a Windows machine with nothing installed.
        //
        // What it costs is the dialect-SPECIFIC backends, and the run says so rather than silently
        // choosing one. The dialect-neutral core formats anyway, which is why it exists.
        $dialect = $resolved->dialect ?? Dialect::Pgsql;

        if (! $resolved->dialect instanceof Dialect) {
            $this->report('sqlens:format: '.$resolved->reason.' — '.$resolved->detail);
        }

        $resolution = $formatters->resolve($backend, $dialect, $settings->style, dialectResolved: $resolved->dialect instanceof Dialect);

        // NAMED before anything is formatted, and the strict refusal happens here rather than after
        // the loop: a run that is going to fail because a backend is missing should not first
        // rewrite two hundred files with a different one.
        $strict = $this->strictToolsOverride() ?? (bool) $config->get('sqlens.strict_tools', false);

        foreach ($resolution->passedOver as $missing) {
            $this->report(sprintf(
                'sqlens:format: %s — `%s` is not installed, so this run used a different backend. It would have added %s',
                BackendDegradation::id($missing),
                $missing,
                BackendDegradation::whatItEnables($missing),
            ));
        }

        if ($strict && $resolution->passedOver !== []) {
            // The whole point of strict tool mode: on a machine where the preferred backend is
            // absent, "it formatted fine" and "it formatted with what the project asked for" are
            // different answers, and a pipeline that cannot tell them apart is checking less than
            // it reports. A DELIBERATELY unavailable backend never reaches here — the registry only
            // passes over one it wanted.
            return ExitCode::UndeterminedInStrictMode->value;
        }

        $formatter = $resolution->outcome;

        if ($formatter instanceof FormatResult) {
            $this->report('sqlens:format: '.$formatter->reason?->value.' — '.$formatter->detail);

            return ExitCode::Misconfiguration->value;
        }

        $files = SqlFileScanner::scan($this->paths($paths, $settings->discovery), $settings->discovery);

        // The schema-dump opt-in, made VISIBLE. `database/schema/*` is excluded by default because
        // `schema:dump` rewrites those files from the database anyway; a project that takes the
        // entry out has decided otherwise, and the run says so rather than leaving the decision in
        // a config file nobody reads during a review.
        $dumps = array_values(array_filter($files, static fn (string $file): bool => str_contains(str_replace('\\', '/', $file), '/database/schema/')));

        if ($dumps !== []) {
            $this->report(sprintf(
                // ⚠️ THE PLURAL IS SPELLED OUT, and that is not a style choice. Two guards scan
                // shipped source for a debug leftover by looking for the helper's name followed by
                // an opening parenthesis, and neither knows a string from a statement — so the
                // parenthesised plural of the word for a database export read as a call to it.
                //
                // The sentence was rewritten rather than the guards: a check for a debug helper in
                // shipped code should stay blunt, and the spelled-out phrase is clearer anyway.
                // Naming the pattern here would trip it a third time, which is the trap this whole
                // comment exists inside.
                'sqlens:format: formatting %d generated schema dump file(s) — `database/schema/*` is excluded '
                .'by default and this project took the entry out of `sqlens.format.exclude`. The next '
                .'`schema:dump` overwrites them: %s',
                count($dumps),
                implode(', ', $dumps),
            ));
        }

        if ($files === []) {
            // Silence over an empty scan reads as "everything is formatted", which is the one answer
            // a formatter must not give when it looked at nothing. The message names the extension
            // deliberately: a project whose SQL lives in migration heredocs will find NOTHING here,
            // and needs to be told that rather than left believing its files are clean.
            $this->report('sqlens:format: no .sql files were found in the configured paths. This '
                .'suite formats `.sql` files only — SQL inside a PHP migration\'s heredoc is not '
                .'formatted, because reading a PHP file as SQL destroys it.');

            return ExitCode::Misconfiguration->value;
        }

        // TWO flags, not one, and they are deliberately not the same question.
        //
        //   --check  is a VERDICT: it moves the exit code.
        //   --diff   is a VIEW:    it shows the work and leaves the exit code alone.
        //
        // Either one suppresses the write. Folding them into a single "not writing" boolean was the
        // first draft and it made `--diff` a second, undocumented gate — a run that printed a diff
        // and failed the build would be a surprise the help text never promised.
        $showDiff = $this->option('diff') === true;
        $writes = $this->option('check') !== true && ! $showDiff;

        $changed = [];
        $unchanged = [];
        // Path and reason apart, not one joined string. The console joins them back with a colon;
        // JSON and a GitHub annotation both need the path as a field of its own, and re-splitting a
        // line on its first colon would break on the first Windows path anybody hands this.
        $undetermined = [];
        // Taken from a RESULT rather than probed separately: the version that formatted these files
        // is the one worth reporting, and a second probe could answer about a different binary if
        // the path changed mid-run.
        $lastVersion = null;

        foreach ($files as $file) {
            // Read through the FILESYSTEM SEAM, not through a bare `file_get_contents`, and judged
            // before the formatter sees anything.
            //
            // The judgment is the point: a bare read answers `false` for a file it cannot open, and
            // the cast that used to stand here turned that into an empty string — which the
            // formatter then quite correctly called "the statement is empty". Correct about the
            // string it was handed, and about nothing the user has: it sent a reader to look at
            // their SQL when the problem was a mode bit.
            //
            // ⚠️ THE SEAM IS WHY THIS IS COVERABLE AT ALL, and the first version was not. A `0000`
            // file is unreadable for an ordinary user and perfectly readable for ROOT, which is what
            // CI runs as — so the arms staged that way skipped there, the branch never executed, and
            // the 100% floor went red on this very block. Nor is there any other filesystem state
            // that reaches it: {@see SqlFileScanner} only yields paths where `is_file()` holds, so a
            // dangling symlink or a directory named `x.sql` is filtered out before the read.
            //
            // Through the container's `Filesystem` the case is stageable anywhere, by anyone,
            // without depending on who the process happens to be.
            try {
                $original = $filesystem->get($file);
            } catch (FileNotFoundException) {
                $original = false;
            }

            if ($original === false) {
                $undetermined[] = ['path' => $file, 'reason' => FormatUndeterminedReason::FileUnreadable->value
                    .' — the file could not be read; check its permissions, and whether it is a link to something that is gone'];

                continue;
            }
            $result = $formatter->format($original, $dialect, $settings->style);

            $lastVersion ??= $result->toolVersion;

            if (! $result->isFormatted()) {
                // NAMED, never skipped. A formatter that passed over what it could not parse would
                // report a clean tree while leaving the one file somebody needs to look at untouched.
                $undetermined[] = ['path' => $file, 'reason' => $result->reason?->value.($result->detail === null ? '' : ' — '.$result->detail)];

                continue;
            }

            if ($result->sql === $original) {
                $unchanged[] = $file;

                continue;
            }

            $changed[] = $file;

            if ($showDiff) {
                $this->report(UnifiedDiff::between($original, (string) $result->sql, $file));
            }

            if ($writes) {
                SafeFileWriter::write($file, (string) $result->sql);
            }
        }

        return $this->verdict(
            $format,
            [
                // The mode names what the run DID, and it is what tells a machine reader whether
                // `formatted` above means "was" or "would be". `--check --diff` reports `check`,
                // because the mode follows the exit code and `--diff` never moves one.
                'mode' => $writes ? 'write' : ($this->option('check') === true ? 'check' : 'diff'),
                'backend' => $formatter->name(),
                'tool_version' => $lastVersion,
                'dialect' => $dialect->value,
                'style_fingerprint' => $settings->style->fingerprint(),
                'strict_tools' => $strict,
                'sqlens' => PackageVersion::current(),
            ],
            count($files),
            $changed,
            $unchanged,
            $undetermined,
        );
    }

    /**
     * Render the run in the requested format, then answer the question the exit code answers.
     *
     * Rendering and the verdict are separate on purpose, and the separation is the reporter
     * contract's own rule stated locally: a reporter RENDERS a result, it does not decide the exit
     * code. Three formats, one verdict — so `--format` can never change whether a build passes.
     *
     * @param  array{mode: string, backend: string, tool_version: string|null, dialect: string, style_fingerprint: string, strict_tools: bool, sqlens: string}  $run
     * @param  list<string>  $changed
     * @param  list<string>  $unchanged
     * @param  list<array{path: string, reason: string}>  $undetermined
     */
    private function verdict(string $format, array $run, int $scanned, array $changed, array $unchanged, array $undetermined): int
    {
        if ($format === 'json') {
            $this->emitJson($run, $scanned, $changed, $unchanged, $undetermined);
        } elseif ($format === 'github') {
            $this->emitGithub($run, $scanned, $changed, $undetermined);
        } else {
            $this->emitConsole($run, $scanned, $changed, $undetermined);
        }

        // An undetermined file moves the exit code in BOTH modes. In `--check` it is obvious; in a
        // write run it matters more, because the tree now holds a mix of formatted files and one
        // nobody could format, and a clean exit would say otherwise.
        if ($undetermined !== []) {
            return ExitCode::UndeterminedInStrictMode->value;
        }

        return $run['mode'] === 'check' && $changed !== [] ? ExitCode::FindingsAboveGate->value : ExitCode::Clean->value;
    }

    /**
     * The human report, on STDERR — see {@see report()} for why that is the right stream here.
     *
     * @param  array{mode: string, backend: string, tool_version: string|null, dialect: string, style_fingerprint: string, strict_tools: bool, sqlens: string}  $run
     * @param  list<string>  $changed
     * @param  list<array{path: string, reason: string}>  $undetermined
     */
    private function emitConsole(array $run, int $scanned, array $changed, array $undetermined): void
    {
        // The WORDING follows what happened to the files; the EXIT CODE follows what was asked.
        // Under `--diff` nothing was written, so "rewritten" would be a lie — and nothing was
        // gated either, so a non-zero exit would be a different lie.
        //
        // The run parameters, and each answers a different question a reader has when two machines
        // formatted one file differently: which backend, which version of it, which dialect, which
        // style, and whether a missing backend was allowed to pass. Without them the difference is a
        // mystery, and the commonest cause — one machine had a binary the other did not — is
        // invisible.
        //
        // ⚠️ `strict tools` is printed in BOTH states, unlike the tool version below, and the
        // asymmetry is deliberate. An absent version says "the built-in core produced this" all by
        // itself, so `(none)` would be noise. A missing strict flag says nothing at all — and it is
        // the one parameter that decides whether a run that lost a backend FAILED or merely said so.
        // Two runs that disagree about that disagree about their exit code, which is exactly the
        // difference a reader is trying to explain.
        $this->report(sprintf(
            'sqlens:format: %s%s (%s, style %s, strict tools %s) — %d file(s) scanned, %d %s, %d undetermined',
            $run['backend'],
            // Only external backends have one. Printing `(none)` for the built-in core would be
            // noise on the common case; its absence already says the core produced this.
            $run['tool_version'] === null ? '' : ' '.$run['tool_version'],
            $run['dialect'],
            $run['style_fingerprint'],
            $run['strict_tools'] ? 'on' : 'off',
            $scanned,
            count($changed),
            $run['mode'] === 'write' ? 'rewritten' : 'would change',
            count($undetermined),
        ));

        foreach ($changed as $file) {
            $this->report(($run['mode'] === 'write' ? 'reformatted: ' : 'would reformat: ').$file);
        }

        foreach ($undetermined as $entry) {
            $this->report('undetermined: '.$entry['path'].': '.$entry['reason']);
        }
    }

    /**
     * The machine report, on STDOUT, so `--format=json > report.json` yields a parseable file.
     *
     * The stream split is the package's rule read the other way round: the REPORT goes to STDOUT and
     * everything that is not the report goes to STDERR. `sqlens:format` had no machine report until
     * now, so everything it said was "not the report" — which is why the console verdict stays on
     * STDERR and is not a stream inconsistency. A degradation notice still reaches a human while the
     * file a pipeline reads holds nothing but JSON.
     *
     * EVERY scanned file appears, including the unchanged ones. The console names only what moved,
     * because a human reading two hundred `unchanged` lines stops reading; a machine filtering them
     * costs nothing, and their absence would make "did this run even look at that file?"
     * unanswerable from the artifact.
     *
     * `outcome: formatted` means "was formatted" in a write run and "would be" under `--check`.
     * That distinction lives in `run.mode`, once, rather than being spelled into every file entry —
     * the three-valued vocabulary this package uses everywhere is `formatted`/`unchanged`/
     * `undetermined`, and a fourth value would fork it for one flag.
     *
     * @param  array{mode: string, backend: string, tool_version: string|null, dialect: string, style_fingerprint: string, strict_tools: bool, sqlens: string}  $run
     * @param  list<string>  $changed
     * @param  list<string>  $unchanged
     * @param  list<array{path: string, reason: string}>  $undetermined
     */
    private function emitJson(array $run, int $scanned, array $changed, array $unchanged, array $undetermined): void
    {
        $files = [];

        foreach ($changed as $path) {
            $files[] = ['path' => $path, 'outcome' => 'formatted', 'reason' => null];
        }

        foreach ($unchanged as $path) {
            $files[] = ['path' => $path, 'outcome' => 'unchanged', 'reason' => null];
        }

        foreach ($undetermined as $entry) {
            $files[] = ['path' => $entry['path'], 'outcome' => 'undetermined', 'reason' => $entry['reason']];
        }

        // Merging three lists destroys the scanner's order, so the artifact is sorted by path
        // rather than left to depend on how many files happened to change. Determinism is the
        // survival condition of a committed artifact: a diff on every run and a team stops reading.
        usort($files, static fn (array $left, array $right): int => strcmp($left['path'], $right['path']));

        $this->line((string) json_encode([
            'run' => $run,
            'files' => $files,
            'summary' => [
                'scanned' => $scanned,
                'changed' => count($changed),
                'unchanged' => count($unchanged),
                'undetermined' => count($undetermined),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * GitHub workflow commands, on STDOUT, where the runner reads them.
     *
     * The annotation WEIGHT tracks the exit code rather than the wording, and that lockstep is the
     * point: a pull request shows three visual weights and nothing else, so an `::error` beside a
     * green check — or a `::notice` beside a red one — teaches a reviewer to distrust both. Under
     * `--check` an unformatted file fails the build, so it is an error; in a write run it was fixed,
     * so it is a notice. An undetermined file fails either way, so it is always an error.
     *
     * Unchanged files get no annotation. Two hundred green ticks are what the ten-per-level cap
     * would spend itself on, leaving the files somebody has to act on unshown.
     *
     * @param  array{mode: string, backend: string, tool_version: string|null, dialect: string, style_fingerprint: string, strict_tools: bool, sqlens: string}  $run
     * @param  list<string>  $changed
     * @param  list<array{path: string, reason: string}>  $undetermined
     */
    private function emitGithub(array $run, int $scanned, array $changed, array $undetermined): void
    {
        // The reproducibility preamble, carrying the same run parameters the console header names.
        // Without it the annotations say which files, and nothing says which backend produced them —
        // and "it is formatted on my machine" is exactly the argument they exist to settle.
        $this->line('::notice title=SQLens '.WorkflowCommandEscaping::property($run['sqlens']).'::'.WorkflowCommandEscaping::data(sprintf(
            'sqlens:format %s — %s%s (%s, style %s, strict tools %s): %d file(s) scanned, %d %s, %d undetermined',
            $run['mode'],
            $run['backend'],
            $run['tool_version'] === null ? '' : ' '.$run['tool_version'],
            $run['dialect'],
            $run['style_fingerprint'],
            $run['strict_tools'] ? 'on' : 'off',
            $scanned,
            count($changed),
            $run['mode'] === 'write' ? 'rewritten' : 'would change',
            count($undetermined),
        )));

        $this->annotate(
            $run['mode'] === 'check' ? 'error' : 'notice',
            array_map(static fn (string $path): array => [
                'path' => $path,
                'message' => $run['mode'] === 'write'
                    ? 'Reformatted by sqlens:format.'
                    : 'This file is not formatted. Run sqlens:format to rewrite it.',
            ], $changed),
        );

        $this->annotate('error', array_map(static fn (array $entry): array => [
            'path' => $entry['path'],
            'message' => 'sqlens:format could not format this file: '.$entry['reason'],
        ], $undetermined));
    }

    /**
     * Emit one annotation per entry, up to the cap, then say how many were withheld.
     *
     * The last line is the whole reason this helper exists. GitHub drops everything past its limit
     * WITHOUT saying so, which turns a truncated list into a shorter list — the silent-green shape
     * this package refuses everywhere else.
     *
     * @param  list<array{path: string, message: string}>  $entries
     */
    private function annotate(string $weight, array $entries): void
    {
        // One slot short of the cap when there is an overflow, so the line announcing it is itself
        // displayed rather than being the eleventh thing GitHub drops.
        $budget = count($entries) > self::ANNOTATION_LIMIT ? self::ANNOTATION_LIMIT - 1 : count($entries);

        foreach (array_slice($entries, 0, $budget) as $entry) {
            $this->line('::'.$weight.' file='.WorkflowCommandEscaping::property($entry['path']).'::'
                .WorkflowCommandEscaping::data($entry['message']));
        }

        $withheld = array_slice($entries, $budget);

        if ($withheld === []) {
            return;
        }

        $this->line('::'.$weight.'::'.WorkflowCommandEscaping::data(sprintf(
            '%d more file(s) were not annotated (GitHub caps annotations at %d per level); '
            .'--format=json carries the full list. Omitted: %s',
            count($withheld),
            self::ANNOTATION_LIMIT,
            implode(', ', array_column($withheld, 'path')),
        )));
    }

    /**
     * Where to look. Three sources, most specific first.
     *
     *   1. the command line — positional arguments and `--path=`, unioned
     *   2. `sqlens.format.paths`, when the project named its own roots
     *   3. `MigrationPaths`, the same resolution every other command uses
     *
     * ⚠️ Step 2 is new, and the docblock here used to argue against it: "a formatter that scanned a
     * different set than the linter judges would rewrite files nothing checks and skip files
     * something does". The reasoning is about MIGRATIONS and does not reach this suite — the linter
     * judges `.php` migrations and the formatter takes `.sql` files only, so the two sets are
     * already disjoint by construction. What the old default really did was leave a project whose
     * SQL lives outside its migration paths with no way to say so, short of naming the directory on
     * every invocation.
     *
     * The fallback is unchanged, so a project that configures nothing behaves exactly as before.
     *
     * @return list<string>
     */
    private function paths(MigrationPaths $paths, FormatDiscovery $discovery): array
    {
        // `--path` is declared repeatable, so Laravel always hands back an array — the `is_array`
        // a first draft had here was a branch nothing can enter, which is a branch no test can
        // cover and no reader can trust.
        $named = array_values(array_filter((array) $this->option('path'), is_string(...)));
        $positional = array_values(array_filter((array) $this->argument('path'), is_string(...)));

        // UNION, not one-or-the-other. `sqlens:format a.sql --path=b.sql` names two files, and a run
        // that silently dropped either would format a tree nobody asked for or skip one somebody
        // did.
        //
        // ⚠️ NOT deduplicated here, and the first draft was — with a comment claiming that without
        // it the summary would count a doubly-named file twice. It would not: {@see SqlFileScanner}
        // already makes its result unique, for the overlapping-configured-paths case, and a red
        // proof over the extra `array_unique` came back GREEN. A second guard whose stated reason is
        // already handled elsewhere is worse than none — the next reader believes the reason.
        $selected = [...$positional, ...$named];

        if ($selected !== []) {
            return $selected;
        }

        return $discovery->roots === [] ? $paths->all() : $discovery->roots;
    }

    /**
     * Everything that is NOT a machine report goes to STDERR through here.
     *
     * Named `report` rather than `line` because `Command::line()` already exists and means something
     * else — an override would silently change where every inherited helper writes. And STDERR
     * rather than STDOUT so a `--check` run can be piped without its verdict landing in whatever is
     * reading the pipe.
     *
     * ⚠️ The first line used to read "everything this command says", and `--format` made that false.
     * The rule it always meant is the package's: the report on STDOUT, everything else on STDERR.
     * With one format there was no report, so "everything else" was everything. The console verdict
     * stays here deliberately — a human reading a write run wants it beside the degradation notices,
     * not mixed into a file somebody is piping.
     */
    private function report(string $message): void
    {
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($message);
    }
}
