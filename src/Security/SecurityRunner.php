<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Audit\AuditOutcome;
use Pushery\SQLens\Audit\AuditRuns;
use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Lint\LintOutcome;
use Pushery\SQLens\Lint\LintRuns;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Security\Analyse\AnalyseBridge;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * The security run: the `security` category, gathered across the suites that can produce it.
 *
 * A thin aggregator over services that already exist, and deliberately nothing more. There is no
 * second engine here, no copied orchestration and no rule — the guarantee is that the same input
 * yields the findings a single-suite run would produce, and the only way to keep that true is to
 * CALL those runs rather than reimplement them.
 *
 * ## Two sub-runs, not three — and the plan said three
 *
 * It named lint, the audit catalog, and the security readers as three sources. Measured, the third
 * is not a service: `AuditRunner` drives the security readers itself and turns their readings into
 * subjects the same dispatcher walks. A third call would read the same catalogs a second time over a
 * second session and report the same facts twice — the second engine the plan forbids two lines
 * further down. So the security readings arrive THROUGH the audit, and this calls two runs.
 *
 * ## Why a failed sub-run is a finding rather than a shorter report
 *
 * A project with no migrations, a connection the lint half cannot reach, a role without the
 * privileges — each makes one sub-run impossible, and each is ordinary rather than exceptional. A
 * run that quietly returned the other half would report fewer findings and look like a cleaner
 * database. So a sub-run that cannot happen contributes a named `undetermined` finding, and the
 * aggregate says which half is missing.
 *
 * ## What it does NOT do
 *
 * **Deduplicate.** Two suites can legitimately report the same rule about one object, and deciding
 * which survives is its own change with its own arguments. Concatenating is the honest interim: a
 * duplicate is visible and fixable, a wrongly-dropped finding is neither.
 *
 * **Assemble a run context.** It returns the audit's when the audit ran — that is the half which
 * addressed an instance, so it carries the server version, the pooler verdict and the instance
 * identity — and null when it did not. A context invented here would be a second header for a run
 * that already has one, and the two would drift.
 */
final readonly class SecurityRunner
{
    /** The one category this run is about, set here rather than by every caller. */
    public const string CATEGORY = 'security';

    public function __construct(
        private AuditRuns $audit,
        private LintRuns $lint,
        /**
         * The injection half, or null when nothing wired one.
         *
         * Optional and absent by default for the same reason `$environment` is on the privacy rules:
         * this class is constructed in places that have no container, and a half that assembled
         * itself would read configuration from inside a runner. Absent, the half reports that it did
         * not run — never that it found nothing.
         */
        private ?AnalyseBridge $analyse = null,
    ) {}

    /**
     * Run both halves and return what they found, with the failure of either named.
     *
     * @param  list<string>|null  $migrationPaths  where to look for migrations; null means the configured paths
     * @param  string|null  $host  the ONE read host to address when the connection configures a choice.
     *                             Only the audit half reads an instance; the lint half never does. Without
     *                             it a split connection refuses with CAP.L0.INSTANCE_AMBIGUOUS -- correctly,
     *                             because choosing a host for somebody is exactly what this package must not
     *                             do -- and until this parameter existed there was no way to answer it,
     *                             which made the suite unusable on the split topologies it is for.
     * @param  bool|null  $strictTools  override the configured strict_tools, or null to keep it. Reaches BOTH
     *                                  halves: a flag that made one of them strict and left the other on the
     *                                  configured value would produce a run nobody asked for and no header names.
     */
    public function run(?string $connection = null, ?array $migrationPaths = null, ?bool $strictUndetermined = null, ?bool $strictTools = null, ?string $host = null): SecurityOutcome
    {
        $audit = $this->audit($connection, $strictUndetermined, $strictTools, $host);
        $lint = $this->lint($connection, $migrationPaths, $strictTools);
        $analyse = $this->analyse($audit->context ?? $lint->context);

        return new SecurityOutcome(
            // Ordered here rather than left as two concatenated halves. Both sub-runs sort their own
            // output by LOCATION, which is how a migration or a schema is read — and concatenating
            // two sorted lists is not a sorted list. A security report is triaged instead of read
            // top to bottom, so the aggregate carries its own order: worst first.
            SecurityFindingOrder::sorted([...$audit->findings, ...$lint->findings, ...$analyse->findings]),
            $audit->context,
            $audit->reached,
            $lint->reached,
            $analyse->reached,
        );
    }

    /**
     * The live half: the audit, narrowed to this one category.
     *
     * The security readers ride along inside it, which is why there is no separate call for them.
     */
    private function audit(?string $connection, ?bool $strictUndetermined, ?bool $strictTools, ?string $host): SecuritySubRun
    {
        try {
            $outcome = $this->audit->run(
                $connection,
                $host,
                // No level. A security finding is weighed on the SEVERITY axis, and passing a level
                // here would let a project's strictness appetite silently withhold a security rule —
                // the one thing the two-axis model exists to prevent.
                null,
                [self::CATEGORY],
                $strictUndetermined,
                strictTools: $strictTools,
            );

            return $this->fromAudit($outcome, $connection);
        } catch (Throwable $exception) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunCrashed('audit', $exception->getMessage()));
        }
    }

    /**
     * Whether the audit half actually examined the target, read from its OUTCOME.
     *
     * This is the correction that matters most in this file, and it was measured rather than
     * reasoned about. The first version treated "did not throw" as "ran" — and on an unsupported
     * driver the audit does not throw at all: it returns `Misconfiguration` with `unsupported` set
     * and zero findings. The security run then reported no findings and exit 0 over a connection it
     * had never examined, which is the exact silent green this suite exists to refuse. A probe
     * against sqlite produced it on the first try.
     *
     * A misconfiguration is likewise not a shorter report: an ambiguous connection, an unknown
     * category, a config the package cannot read — none of them looked at anything.
     */
    private function fromAudit(AuditOutcome $outcome, ?string $requested): SecuritySubRun
    {
        if ($outcome->unsupported instanceof DriverResolutionFailure) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunUnsupported('audit', $this->named($requested, $outcome->connectionName)));
        }

        if ($outcome->exitCode === ExitCode::Misconfiguration) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunRefused('audit', $outcome->result->findings));
        }

        return SecuritySubRun::reached($outcome->result->findings, $outcome->context);
    }

    /**
     * The connection a reader would recognize: the one they ASKED for, when they asked for one.
     *
     * A sub-run that refused before resolving reports `unresolved` as its connection name, which is
     * true of the run and useless to somebody who typed `--connection=sqlite` and is told a
     * connection called "unresolved" is unsupported. The requested name wins where there is one.
     */
    private function named(?string $requested, string $resolved): string
    {
        return $requested !== null && $requested !== '' ? $requested : $resolved;
    }

    /** The same question for the migration half, asked of its own outcome. */
    private function fromLint(LintOutcome $outcome, ?string $requested): SecuritySubRun
    {
        if ($outcome->unsupported instanceof DriverResolutionFailure) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunUnsupported('lint', $this->named($requested, $outcome->connectionName)));
        }

        if ($outcome->exitCode === ExitCode::Misconfiguration) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunRefused('lint', $outcome->result->findings));
        }

        return SecuritySubRun::reached($outcome->result->findings, $outcome->context);
    }

    /**
     * The injection half: what PHPStan found, read rather than run.
     *
     * It takes the context the live halves established instead of assembling one, because a context
     * is a statement about an INSTANCE — server version, pooler verdict, the schemas in scope — and
     * this half addresses no instance at all. Inventing one from defaults would put a made-up server
     * version beside a finding about a PHP file.
     *
     * When neither live half produced a context there is none to borrow, and the half says it did not
     * run. That is the honest answer: without a context the finding could not carry the driver and
     * profile every other finding in the report carries, and a report whose rows disagree about what
     * they describe is worse than one row short.
     */
    private function analyse(?RunContext $context): SecuritySubRun
    {
        if (! $this->analyse instanceof AnalyseBridge) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunNotConfigured(
                'analyse',
                'nothing wired the injection half into this run, so no raw-SQL call site was examined',
            ));
        }

        if (! $context instanceof RunContext) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunNotConfigured(
                'analyse',
                'neither live half established a run context, so an injection finding would have had '
                .'no driver and no profile to carry',
            ));
        }

        $reading = $this->analyse->read(new SubjectContext(
            // A raw-SQL call site is a fact about a PHP file, so it names no engine. `unknown` is the
            // established spelling for that here (AuditNotices does the same), and it is the honest
            // one: borrowing the run's driver would attach `pgsql` to a finding that would read
            // identically on MySQL.
            driver: 'unknown',
            profile: $context->profile->value,
            strictTools: $context->strictTools,
        ));

        return $reading->reason === null
            ? SecuritySubRun::reached($reading->findings, $context)
            : SecuritySubRun::failed(SecurityRunNotices::subRunNotConfigured('analyse', $reading->reason));
    }

    /**
     * The migration half: the lint suite, narrowed the same way.
     *
     * `Pretend` rather than `Shadow`, and not as a default a caller may change: shadow mode CREATES
     * a database. A security run that provisioned one to answer a question about safety would be
     * the tool doing the thing it exists to warn about, so the choice is made here and not exposed.
     *
     * @param  list<string>|null  $migrationPaths
     */
    private function lint(?string $connection, ?array $migrationPaths, ?bool $strictTools): SecuritySubRun
    {
        try {
            $outcome = $this->lint->run(
                $connection,
                $migrationPaths,
                CaptureMode::Pretend,
                null,
                null,
                [self::CATEGORY],
                strictTools: $strictTools,
            );

            return $this->fromLint($outcome, $connection);
        } catch (Throwable $exception) {
            return SecuritySubRun::failed(SecurityRunNotices::subRunCrashed('lint', $exception->getMessage()));
        }
    }
}
