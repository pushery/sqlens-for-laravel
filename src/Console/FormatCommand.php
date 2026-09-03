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
use Pushery\SQLens\Format\FormatResult;
use Pushery\SQLens\Format\FormatterRegistry;
use Pushery\SQLens\Format\FormatUndeterminedReason;
use Pushery\SQLens\Format\SafeFileWriter;
use Pushery\SQLens\Format\SqlFileScanner;
use Pushery\SQLens\Format\UnifiedDiff;
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
 */
final class FormatCommand extends Command
{
    use ResolvesStrictTools;

    /** @var string */
    protected $signature = 'sqlens:format
        {--path=* : A path to format; repeatable. Defaults to the application\'s registered migration paths}
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

        $files = SqlFileScanner::scan($this->paths($paths));

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
                $undetermined[] = $file.': '.FormatUndeterminedReason::FileUnreadable->value
                    .' — the file could not be read; check its permissions, and whether it is a link to something that is gone';

                continue;
            }
            $result = $formatter->format($original, $dialect, $settings->style);

            $lastVersion ??= $result->toolVersion;

            if (! $result->isFormatted()) {
                // NAMED, never skipped. A formatter that passed over what it could not parse would
                // report a clean tree while leaving the one file somebody needs to look at untouched.
                $undetermined[] = $file.': '.$result->reason?->value.($result->detail === null ? '' : ' — '.$result->detail);

                continue;
            }

            if ($result->sql === $original) {
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
            $formatter->name(),
            $lastVersion,
            $settings->style->fingerprint(),
            $dialect,
            count($files),
            $changed,
            $undetermined,
            $writes,
        );
    }

    /**
     * @param  list<string>  $changed
     * @param  list<string>  $undetermined
     */
    private function verdict(string $backend, ?string $toolVersion, string $styleFingerprint, Dialect $dialect, int $scanned, array $changed, array $undetermined, bool $wrote): int
    {
        // The WORDING follows what happened to the files; the EXIT CODE follows what was asked.
        // Under `--diff` nothing was written, so "rewritten" would be a lie — and nothing was
        // gated either, so a non-zero exit would be a different lie.
        $checking = $this->option('check') === true;

        // FIVE facts on every run, and each answers a different question a reader has when two
        // machines formatted one file differently: which backend, which version of it, which
        // dialect, and which style. Without them the difference is a mystery, and the commonest
        // cause — one machine had a binary the other did not — is invisible.
        $this->report(sprintf(
            'sqlens:format: %s%s (%s, style %s) — %d file(s) scanned, %d %s, %d undetermined',
            $backend,
            // Only external backends have one. Printing `(none)` for the built-in core would be
            // noise on the common case; its absence already says the core produced this.
            $toolVersion === null ? '' : ' '.$toolVersion,
            $dialect->value,
            $styleFingerprint,
            $scanned,
            count($changed),
            $wrote ? 'rewritten' : 'would change',
            count($undetermined),
        ));

        foreach ($changed as $file) {
            $this->report(($wrote ? 'reformatted: ' : 'would reformat: ').$file);
        }

        foreach ($undetermined as $line) {
            $this->report('undetermined: '.$line);
        }

        // An undetermined file moves the exit code in BOTH modes. In `--check` it is obvious; in a
        // write run it matters more, because the tree now holds a mix of formatted files and one
        // nobody could format, and a clean exit would say otherwise.
        if ($undetermined !== []) {
            return ExitCode::UndeterminedInStrictMode->value;
        }

        return $checking && $changed !== [] ? ExitCode::FindingsAboveGate->value : ExitCode::Clean->value;
    }

    /**
     * Where to look, from the flag or from the same resolution every other command uses.
     *
     * Through `MigrationPaths` rather than a second reading of the config: a formatter that scanned
     * a different set than the linter judges would rewrite files nothing checks and skip files
     * something does.
     *
     * @return list<string>
     */
    private function paths(MigrationPaths $paths): array
    {
        // `--path` is declared repeatable, so Laravel always hands back an array — the `is_array`
        // a first draft had here was a branch nothing can enter, which is a branch no test can
        // cover and no reader can trust.
        $named = array_values(array_filter((array) $this->option('path'), is_string(...)));

        if ($named !== []) {
            return $named;
        }

        return $paths->all();
    }

    /**
     * Everything this command says goes to STDERR.
     *
     * Named `report` rather than `line` because `Command::line()` already exists and means something
     * else — an override would silently change where every inherited helper writes. And STDERR
     * rather than STDOUT so a `--check` run can be piped without its verdict landing in whatever is
     * reading the pipe.
     */
    private function report(string $message): void
    {
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($message);
    }
}
