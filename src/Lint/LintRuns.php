<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Deploy\DebtMode;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * The seam between a caller and the lint run it drives.
 *
 * The audit half has had one since it was written, for a reason its own docblock states: driving a
 * command's four exit codes through a real reading means building four database states to exercise
 * four `return` statements. The lint half never got one, and the asymmetry only became a problem
 * when something needed to CALL both — the security run aggregates them, and `LintRunner` is `final
 * readonly` with no contract, so half of that aggregation could not be tested at all.
 *
 * Extracted rather than invented: the signature below is the runner's, unchanged. What is new is
 * only that a caller may depend on the shape instead of the class.
 */
interface LintRuns
{
    /**
     * Run the lint suite over a connection, or the resolved default, capturing the pending
     * migrations found under the given paths.
     *
     * @param  list<string>|null  $migrationPaths  null means the application's registered paths
     * @param  list<string>  $files  the migration files this run judges instead of the pending set (empty = the pending set)
     * @param  list<string>|null  $categories  category values to scope to (null = the config's, empty = all)
     * @param  bool  $applyBaseline  whether to suppress against the configured baseline
     * @param  list<Finding>  $crossSuiteFindings  the audit half's visible findings, when a security run brought them
     */
    public function run(
        ?string $connection,
        ?array $migrationPaths,
        CaptureMode $mode,
        ?string $assumeServerVersion = null,
        ?int $level = null,
        ?array $categories = null,
        bool $applyBaseline = true,
        ?bool $strictTools = null,
        /**
         * The migration FILES this run judges instead of the pending set — the DB-free fast path.
         *
         * A list, and it took one string until `--file` started accepting several. The option had
         * declared itself repeatable all along (`--file=*`, and Symfony's own help said so), while
         * the command refused a second value: a pre-commit hook over 53 staged migrations paid one
         * artisan boot per file for a run that should have been one.
         *
         * @var list<string>
         */
        array $files = [],
        ?GuardDecision $guard = null,
        bool $roundtrip = false,
        /**
         * What this run may do with the debt account. Null means the caller did not ask, which is
         * NOT the same as `check`: a caller that never heard of the account gets no debt pass at
         * all, so adding this parameter changed no existing behavior.
         */
        ?DebtMode $debt = null,
        /**
         * Whether a migration discovered inside `vendor/` is enumerated at all.
         *
         * Null means "read `sqlens.security.include_vendor_migrations`", which is what every
         * ordinary caller wants: a finding inside somebody else's package is one a team cannot act
         * on, repeated on every run, and a rule that cannot be acted on is one people silence
         * wholesale.
         *
         * A caller passes TRUE when its question is a different one. `sqlens:predeploy` does,
         * because a package's migration really does run during a deploy and really can take a lock.
         *
         * A run whose paths were NAMED — `--path`, `sqlens.migration_paths`, `--file` — is never
         * filtered, whatever this says: naming a path is a person saying "these".
         */
        ?bool $includeVendorMigrations = null,
        /**
         * What the AUDIT half of the same security run reported and still shows.
         *
         * Only the cross-source dedupe reads them, and only their catalog side: it hides a migration
         * finding about a `GRANT … TO PUBLIC` when the catalog half reported that same grant. That
         * layer had never once fired, because `sqlens:security` resolves its two halves in separate
         * passes and neither pass could see both sides of one fact.
         *
         * Empty for every caller that runs the lint suite alone, and that is the honest value rather
         * than an unset one: a lone lint run HAS no catalog half, so there is nothing a collapse
         * could stand in for.
         *
         * @var list<Finding>
         */
        array $crossSuiteFindings = [],
    ): LintOutcome;
}
