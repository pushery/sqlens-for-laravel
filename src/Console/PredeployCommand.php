<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Deploy\PreflightReport;
use Pushery\SQLens\Deploy\PreflightRuns;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\ReporterManager;
use Pushery\SQLens\Reporting\RunContext;
use Symfony\Component\Console\Output\ConsoleOutputInterface;

/**
 * `sqlens:predeploy` — the gate that runs immediately before `migrate --force`.
 *
 * Deliberately thin, like its `sqlens:lint` sibling: it turns options into a run and a run into an
 * exit code, and owns no checking logic of its own. Every question lives in a `PreflightCheck`, and
 * the order they are asked in belongs to the runner.
 *
 * ## Fail-closed is the default, and it is a choice with a cost
 *
 * A run that could not look has not established that the deploy is safe, so `undetermined` blocks.
 * That means a database blip stops a deploy — deliberately, because the `migrate` step two lines
 * later would have failed anyway, and failing at the gate is the cheaper of the two. The deliberate
 * way out is `--allow-undetermined`, and it is a flag rather than a default so that using it is a
 * decision somebody made rather than one nobody noticed.
 *
 * ## The budget is a promise, not a preference
 *
 * A gate that visibly delays a deploy gets configured away in the first sprint, and a gate nobody
 * runs has helped nobody. So the budget is enforced by the runner rather than hoped for — and a
 * check the budget stopped is reported `undetermined`, never quietly dropped.
 */
final class PredeployCommand extends Command
{
    use ResolvesProfile;

    protected $signature = 'sqlens:predeploy
        {--connection= : The database connection to check; defaults to the resolved preflight connection}
        {--profile= : The environment profile — local, ci or predeploy. Unset, this command uses predeploy; SQLENS_PROFILE and a configured profile still win over that}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--budget= : The whole run\'s time budget in milliseconds; the default is configured}
        {--allow-undetermined : Proceed when a check could not answer. Fail-closed is the default, and this is the deliberate way out}';

    protected $description = 'Check the target database immediately before a deploy: read-only, fail-closed, bounded.';

    public function handle(
        PreflightRuns $preflight,
        ReporterManager $reporters,
        Repository $config,
    ): int {
        $requested = $this->option('connection');
        $budget = $this->option('budget');

        // The same resolution every other suite command uses -- flag over SQLENS_PROFILE over the
        // configured profile -- with `predeploy` underneath as this command's own default rather
        // than as an option default.
        //
        // AS AN OPTION DEFAULT IT WAS ALWAYS THE FLAG, and that had two consequences. The
        // environment could not speak: `SQLENS_PROFILE=ci sqlens:predeploy` ran as predeploy, with
        // nothing saying so. And the name never became the SETTINGS: this command did not resolve
        // a profile at all, so the run announced `profile=predeploy` in its header while gating
        // with whatever the base config said. A consumer measured the second half on a production
        // host -- twelve `high` findings, none of them reaching the exit code, because the
        // severity floor was still the lenient one.
        $profile = $this->resolveProfile($config, 'predeploy');

        if (! $profile->isValid()) {
            $this->outputErrorLine($this->profileRejectionMessage($profile));

            return ExitCode::Misconfiguration->value;
        }

        $outcome = $preflight->run(
            connection: is_string($requested) && $requested !== '' ? $requested : null,
            profile: $profile->profile,
            budgetMs: is_string($budget) && ctype_digit($budget) ? (int) $budget : null,
        );

        // A run that never happened is a misconfiguration, not a finding: nothing was learned about
        // the database, and reporting a clean run would be the silent green this gate exists to
        // refuse. The service names the reason; turning it into an exit code is this command's job.
        //
        // Narrowed with `instanceof` rather than a `ran()` predicate, because a method returning
        // bool tells the analyzer nothing about the two nullable properties every line below reads.
        // The check is the language's requirement, not a second decision about the same fact.
        if (! $outcome->report instanceof PreflightReport || ! $outcome->result instanceof Result || ! $outcome->context instanceof RunContext) {
            $this->outputErrorLine((string) $outcome->refusal);

            return ExitCode::Misconfiguration->value;
        }

        // The report goes through the SAME reporters everything else uses, and that is the point
        // rather than reuse: a gate with its own output format would drift from the one a pipeline
        // already parses, and the day the two disagree nobody can tell which is right.
        //
        // The findings travel as findings. A preflight verdict is not a new kind of thing — it is
        // the same three-valued statement about a database that `lint` and `audit` produce, and
        // giving it a private shape would make `downtime_class` and the severity axis stop working
        // exactly where a deploy needs them most.
        try {
            $reporter = $reporters->reporter(is_string($format = $this->option('format')) ? $format : null);
        } catch (UnknownReporterFormat $error) {
            // Refused, never fallen back from. A quiet fall back to console is the worst available
            // answer: the run succeeds, the output is the wrong shape, and whatever was parsing it
            // gets nothing — silently, at the moment before a deploy.
            $this->outputErrorLine($error->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        // `--allow-undetermined` opens exactly one door and no other: a run whose ONLY blockers
        // could not answer proceeds. A real failure still blocks, because that is a fact about the
        // database rather than about this gate's reach. What counts as "only undetermined" is the
        // outcome's own answer, so this command and the MCP tool cannot disagree about whether a
        // deploy proceeds.
        //
        // Decided HERE rather than at the exit-code line further down, because the report has to
        // carry it. A waived run and an earned one otherwise produce the same exit code, the same
        // green tick and the same document — and "predeploy passed" then means two different
        // things nobody can tell apart afterwards. The exit code below reuses this value instead
        // of asking again, so the record and the verdict cannot disagree.
        // Two ways in, one door. The flag is the per-run decision; the config key is the same
        // decision taken once for a project. Neither is a second kind of waiver, so they are joined
        // here rather than checked at two places that could disagree about what "open" means.
        $hatchOpen = $this->option('allow-undetermined') === true
            || $config->get('sqlens.deploy.predeploy.allow_undetermined') === true;

        $waived = $outcome->report->blocks()
            && $outcome->blockedOnlyByUndetermined()
            && $hatchOpen;

        // Both halves as ONE result, and both come from the service. Assembling them here as well
        // would be a second merge of one run, free to differ from the one the MCP tool renders —
        // and a consumer would then have to choose which document is "the" verdict.
        $reporter->report(
            $outcome->result,
            $outcome->context->withUndeterminedWaiver($waived),
            $this->getOutput()->getOutput(),
        );

        if ($outcome->advisory instanceof CatalogSkip) {
            $this->outputErrorLine((string) $outcome->advisory->detail);
        }

        foreach ($outcome->report->undetermined() as $result) {
            $this->outputErrorLine($result->checkId.': '.$result->reason);
        }

        if (! $outcome->report->blocks()) {
            return ExitCode::Clean->value;
        }

        if ($waived) {
            return ExitCode::Clean->value;
        }

        $onlyUndetermined = $outcome->blockedOnlyByUndetermined();

        return $outcome->report->undetermined() !== [] && $onlyUndetermined
            ? ExitCode::UndeterminedInStrictMode->value
            : ExitCode::FindingsAboveGate->value;
    }

    /**
     * Everything that is not the report goes to STDERR, so `--format=json` leaves STDOUT parseable.
     *
     * No empty-line guard. It used to have one and nothing could enter it: every call site passes
     * either an exception message, a check id joined to its reason, or a `CatalogSkip`'s detail —
     * and a skip is never built without one, which is the point of `SkipReason`. Measured at all
     * five call sites, then removed. A guard nothing can trigger is a question every future reader
     * has to answer before concluding it is dead.
     */
    private function outputErrorLine(string $line): void
    {
        // STDERR when the output offers one, so `--format=json` leaves STDOUT with nothing but the
        // document a pipeline parses. A plain output has no error stream and gets the line anyway —
        // losing it would be worse than mixing it in.
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($line);
    }
}
