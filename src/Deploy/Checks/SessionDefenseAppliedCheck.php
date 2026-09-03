<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Contracts\ReadsSessionBounds;
use Pushery\SQLens\Contracts\ReadsSessionDefenseState;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Whether the timeouts this run set on its own session are actually in force.
 *
 * ## A set value is not an assurance; a read-back one is
 *
 * The session issues `SET statement_timeout` and `SET lock_timeout` before it reads anything, and
 * every promise this gate makes about not harming a production database rests on those holding. Under
 * PgBouncer in TRANSACTION pooling mode, session state does not reliably survive the end of a
 * transaction — the `SET` is accepted, returns no error, and quietly stops applying.
 *
 * Nothing about that is visible from the setting side. The command would print the values it asked
 * for, a reader would believe the run was bounded, and a statement that hung would hang for as long
 * as the server allows. That is silent green at the most sensitive point in the whole gate: the
 * place where "this tool cannot hurt your database" is supposed to become true.
 *
 * So the values are READ BACK on the same connection and compared against what was requested. What
 * the report shows is what came back.
 *
 * ## Why a mismatch fails rather than warns
 *
 * A bounded run and an unbounded one are different products. Continuing under an assurance that does
 * not hold is exactly the thing this package refuses everywhere else — and the remedy is concrete:
 * point the preflight at a session-pooled connection, or at the database directly.
 */
final readonly class SessionDefenseAppliedCheck implements PreflightCheck, ReadsSessionBounds
{
    /**
     * No default, and that is the point rather than an oversight.
     *
     * `[]` builds a check that answers `undetermined` for every engine — correct behavior, and
     * indistinguishable from a wiring mistake. It WAS one: 82d95e5b moved the engine question
     * behind this parameter and updated the Unit and Feature arms, while the three sites in
     * `tests/MySql/SessionDefenseAppliedLiveTest.php` kept the argument-less spelling and went on
     * compiling. The pull-request lane does not run that suite, so the first red was the develop
     * push gate — three arms, all of them reading as a live MySQL server refusing to answer.
     *
     * Required, `new SessionDefenseAppliedCheck()` stops being a plausible line: it is an
     * ArgumentCountError the moment it executes, in whatever lane executes it. The one caller that
     * genuinely wants no capabilities passes `[]` and says so.
     *
     * @param  array<string, ReadsSessionDefenseState>  $capabilities  keyed by driver, supplied by
     *                                                                 the composition root — the one
     *                                                                 place allowed to name engines
     */
    public function __construct(private array $capabilities) {}

    public const string ID = 'DEPLOY.CONTEXT.SESSION_DEFENSE_NOT_APPLIED';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return in_array($driver, ['pgsql', 'mysql'], true);
    }

    /**
     * The timeouts actually in force, in milliseconds — the same read this check judges on.
     *
     * Public so the reporter header can show them, and it is the SAME call rather than a second
     * one on purpose. Two reads of one fact are two chances to disagree, and the disagreement would
     * surface as a header claiming a bound beside a verdict saying there is none.
     *
     * @return array<string, int|null>
     *
     * @throws Throwable
     */
    public function inForce(string $driver, ReaderSession $session): array
    {
        $capability = $this->capabilities[$driver] ?? null;

        if (! $capability instanceof ReadsSessionDefenseState) {
            // Thrown rather than answered with an empty map, and the difference is the whole point:
            // an empty map has no unbounded entry in it, so `run()` would read it as a clean pass
            // and report a run as bounded that nobody asked about. The throw comes back as a named
            // `undetermined` one frame up.
            throw new PreflightStateUnreadable(sprintf(
                'no driver capability reads the session timeouts for "%s", so this run cannot say '
                .'whether it is bounded at all',
                $driver,
            ));
        }

        return $capability->timeoutsInForce($session);
    }

    public function run(PreflightContext $context): CheckResult
    {
        try {
            $applied = $this->inForce($context->driver, $context->session);
        } catch (Throwable $error) {
            return CheckResult::undetermined(
                self::ID,
                'the session would not say which timeouts are in force ('.$error->getMessage().'), '
                .'so nothing is known about whether this run is bounded. An unread bound is not a '
                .'bound: the statements that follow could run for as long as the server allows.',
            );
        }

        $missing = array_values(array_filter(
            $applied,
            static fn (?int $value): bool => $value === null || $value === 0,
        ));

        if ($missing === []) {
            return CheckResult::pass(self::ID);
        }

        $unbounded = array_keys(array_filter(
            $applied,
            static fn (?int $value): bool => $value === null || $value === 0,
        ));

        return CheckResult::fail(self::ID, [$this->finding($context, $unbounded)]);
    }

    /** @param list<string> $unbounded */
    private function finding(PreflightContext $context, array $unbounded): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'This run set its own timeouts and the session reports %s as unbounded when read '
                .'back. A `SET` that returns no error can still stop applying — under transaction '
                .'pooling, session state does not survive the end of a transaction — so the run is '
                .'not bounded even though it asked to be. Point the preflight at a session-pooled '
                .'connection, or at the database directly.',
                implode(' and ', $unbounded),
            ),
            location: Location::inCatalog($context->driver, $context->connection, 'session timeouts', SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::High,
        )->withDowntimeClass(DowntimeClass::Online);
    }
}
