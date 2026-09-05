<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Attribution;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * Every finding a deploy run can produce, with the metadata a consumer reads.
 *
 * ## What it fixes
 *
 * Twelve ids emitted a documentation URL and reached no catalog. That means three things a user
 * meets: `sqlens:rules` does not list them, the MCP `explain-rule` tool cannot explain them, and the
 * link inside the finding resolves to nothing. A baseline naming one is rejected as unknown, which
 * is the message written for a typo.
 *
 * ## The three bands, and why the ids say which
 *
 * - **`DEPLOY.PREFLIGHT.*`** — asked immediately BEFORE the migration runs, against the target. They
 *   answer "should this deploy start at all".
 * - **`DEPLOY.CONTEXT.*`** — facts about the target that shape how a finding should be read rather
 *   than whether to go. A read-only replica and a version skew belong here.
 * - **`DEPLOY.LEGACY.*`** — debt the database is already carrying from an EARLIER deploy: an invalid
 *   index, a constraint left unvalidated. Nothing about the migration at hand.
 *
 * The band is part of the id, so a pipeline can filter on it without a lookup table.
 */
final readonly class DeployCheckCatalog
{
    /** The prefix deploy findings report under — the run, not a rule about a statement. */
    public const string MESSAGE_PREFIX = 'sqlens.deploy';

    /**
     * The checks, sorted by id.
     *
     * @return list<DeployCheckMetadata>
     */
    public static function metadata(): array
    {
        $checks = [
            self::readOnlyTarget(),
            self::sessionDefenseNotApplied(),
            self::serverSetting(),
            self::versionSkew(),
            self::constraintNotValidated(),
            self::invalidIndex(),
            self::orphanTransitionObject(),
            self::oscArtifact(),
            self::unenforcedConstraint(),
            self::diskHeadroom(),
            self::inactiveReplicationSlot(),
            self::lockBlocker(),
            self::metadataLockBlocker(),
            self::missingPrivilege(),
            self::ownershipMissing(),
            self::replicationLag(),
            self::invalidIndexNameCollision(),
            self::concurrentlyBlocker(),
            self::statisticsUnread(),
            self::driftUnexpectedInDatabase(),
            self::driftMissingInDatabase(),
            self::driftDivergent(),
            self::driftUncompared(),
            self::timeBudgetExceeded(),
        ];

        usort($checks, static fn (DeployCheckMetadata $a, DeployCheckMetadata $b): int => $a->id <=> $b->id);

        return $checks;
    }

    /**
     * Live in the database, described by no migration — the hotfix-straight-into-production case.
     *
     * MEDIUM rather than high, and the reason is the same one the unvalidated-constraint page gives:
     * this is the class that fires most on a grown environment, where a decade of hand-made indexes
     * is ordinary rather than alarming. A gate that shouts on the first run of a legacy database is
     * a gate somebody switches off, and then none of the three is read again. What raises a specific
     * one is the next `migrate:fresh` on a rebuilt environment, which drops it silently — and that
     * is a fact about the deploy pipeline rather than about the object.
     */
    private static function driftUnexpectedInDatabase(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.DRIFT.UNEXPECTED_IN_DATABASE',
            Severity::Medium,
            self::deploy(),
            [
                'reports that no migration describes the object; it cannot say WHO created it, or when',
                'reads only the object types both catalog readings covered — a type one side could '
                .'not read is a named blind spot rather than an absence',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * Described by the migrations, absent from the database — a migration that failed, was skipped,
     * or was rolled back and never re-applied.
     *
     * HIGH, and it is the one of the three that earns it: the application was written against this
     * object. Usually it is already failing when the report arrives; the case that makes the check
     * worth having is the other one, where nothing reads the object yet and it can stay missing for
     * months without a single error.
     */
    private static function driftMissingInDatabase(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.DRIFT.MISSING_IN_DATABASE',
            Severity::High,
            self::deploy(),
            [
                'cannot tell a migration that FAILED from one that was never run — both leave the '
                .'same absence, and the migration table is the place that answers it',
                'says nothing about WHEN the object went missing; the comparison is of two states, '
                .'not of a history',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * On both sides under one name, described differently.
     *
     * MEDIUM. A divergence is real and it is also the class most exposed to a normalization gap: two
     * spellings of one definition are a finding this check must never produce, and the canonical
     * form is what stands between it and that. The severity says "look at this", not "stop".
     */
    private static function driftDivergent(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.DRIFT.DIVERGENT',
            Severity::Medium,
            self::deploy(),
            [
                'compares the CANONICAL form of each side, so a difference that canonicalization '
                .'erases is invisible here by design — and a difference it fails to erase is a '
                .'finding the tool caused itself',
                'names the attributes that differ, not the reason they differ',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * One object type, on one side, that could not be read — so that slice of the schema was never
     * compared at all.
     *
     * ## Why this is a FOURTH id and not a field on the other three
     *
     * The three above are answers. This one is the absence of an answer, and it is the only one of
     * the four that can be true while the report shows nothing else at all: a run that could not
     * read indexes finds no index drift, and every line of that report is accurate.
     *
     * Giving it its own id is what lets a project accept it deliberately. A managed database that
     * withholds one catalog will produce this finding on every single run, forever; with a shared
     * id, baselining it would also baseline real drift on that object type. Here it is one entry
     * that says exactly what was accepted — "we cannot read sequences on this instance" — and
     * leaves the three answers armed.
     *
     * ## It names NO severity, deliberately
     *
     * Its finding is always `undetermined`, and a severity would put a number on a check that
     * reached no verdict. Same shape and same reason as `DEPLOY.PREFLIGHT.STATISTICS_UNREAD`.
     */
    private static function driftUncompared(): DeployCheckMetadata
    {
        return DeployCheckMetadata::derived(
            'DEPLOY.DRIFT.UNCOMPARED',
            self::deploy(),
            [
                'names the object TYPE and the side that could not be read, never how many objects '
                .'went uncompared — that number is precisely what the failed reading would have said',
                'a run carrying this finding has not established that the schema matches, however '
                .'empty the other three classes came back',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * The run took longer than the project allows — a statement about SQLens, not about the database.
     *
     * ## Why a finding rather than a log line
     *
     * A post-deploy run hangs off the end of every deploy, and that gives it exactly one survival
     * condition: it must not be something people wait for. A gate that visibly delays a deploy gets
     * configured away in the first sprint, and a gate nobody runs has helped nobody. So an overrun
     * travels the same way every other verdict does — through the reporters, with a severity, into
     * whatever a team archives — rather than as a line somebody has to be watching the terminal to
     * see.
     *
     * ## Why `performance` and not `safety`
     *
     * Nothing about the database is wrong. What is wrong is this tool's own cost, and putting that
     * beside an INVALID index under one category would make "safety" mean two different things in
     * one report.
     *
     * ## Why Low, when the whole argument is that it matters
     *
     * Because it is about the tool, and the reader's attention belongs to the schema. `Low` puts it
     * on the record without pushing it past a constraint that is silently unenforced — and the
     * project's lever is the budget itself, which is one config key away.
     *
     * ## It never aborts
     *
     * The run finishes. Stopping at the deadline would destroy exactly the information that says
     * what to fix — the per-check split — and leave a report that is short for a reason nobody can
     * see. Checks the budget stopped are already reported as `undetermined` with that reason named;
     * this is the run's own account of why.
     */
    private static function timeBudgetExceeded(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.RUN.TIME_BUDGET_EXCEEDED',
            Severity::Low,
            self::deploy(),
            [
                'measures WALL CLOCK, so a loaded machine, a slow network hop or a busy server move '
                .'the number as surely as a slow check does — the per-check split beside it is what '
                .'separates the two, and it is in the message for that reason',
                'says the run was slow, never that a particular check is at fault: the split names '
                .'the most expensive one, which is where to look rather than what to blame',
                'has nothing to say about `sqlens:drift`, which carries no budget at all — a shadow '
                .'replay is dominated by the size of the migration history and belongs outside the '
                .'deploy window',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
            category: Category::Performance,
        );
    }

    /** @return list<Suite> the one suite every deploy check belongs to */
    private static function deploy(): array
    {
        return [Suite::Deploy];
    }

    private static function readOnlyTarget(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.CONTEXT.READ_ONLY_TARGET',
            Severity::High,
            self::deploy(),
            [
                'reads the target\'s own view of itself: a connection routed to a replica by a pooler '
                .'or a proxy reports what that replica knows, and the routing layer is invisible here',
                'says the target cannot accept writes, not that the deploy is wrong — pointing a '
                .'migration at a replica is usually a configuration mistake, and this check names it '
                .'rather than deciding it',
            ],
            Attribution::Observed,
            DowntimeClass::Blocking,
        );
    }

    private static function sessionDefenseNotApplied(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.CONTEXT.SESSION_DEFENSE_NOT_APPLIED',
            Severity::High,
            self::deploy(),
            [
                'reports that SQLens\' own session bounds are not in effect for THIS run; it says '
                .'nothing about the timeouts the migration itself sets',
                'a session setting can be overridden after this check ran, so the finding describes '
                .'the state at the moment it looked',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    private static function serverSetting(): DeployCheckMetadata
    {
        return DeployCheckMetadata::derived(
            'DEPLOY.CONTEXT.SETTING',
            self::deploy(),
            [
                'reads the RUNNING value, not the configuration file: a setting changed on disk and '
                .'not yet reloaded is invisible, and one changed for this session only would be read '
                .'as the server\'s',
                'the severity is decided per setting rather than per check — a catalog naming one '
                .'value for all of them would contradict the findings themselves',
                'covers the settings this package knows to matter for a deploy; a setting nobody '
                .'mapped is not reported, and its absence is not a statement that it is safe',
            ],
            Attribution::Observed,
            downtimeClassDerived: true,
        );
    }

    private static function versionSkew(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.CONTEXT.VERSION_SKEW',
            Severity::Info,
            self::deploy(),
            [
                'compares the pinned `assume_server_version` against what the target reports; it '
                .'cannot tell a deliberate pin from a stale one',
                'Info rather than a warning on purpose: a skew is a fact a reader needs when judging '
                .'every other finding in the run, not a reason to stop',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    private static function constraintNotValidated(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.CONSTRAINT_NOT_VALIDATED',
            Severity::Medium,
            self::deploy(),
            [
                'reports debt from an EARLIER deploy, not a property of the migration at hand',
                // The engine's own keyword for this state belongs on the rule page, not here: this
                // catalog is driver-neutral and a guard holds it to that. The page may write the SQL.
                'a constraint added without validation is enforced for new rows and unproven for old '
                .'ones — the check reports that state and does not guess whether the validation is planned',
            ],
            // AUTHORED, and one of only two in this family. The state is not something the run
            // found in the world: a migration wrote `ADD CONSTRAINT … NOT VALID` and no later one
            // validated it, so there is a migration that causes this and a migration that avoids
            // it. That is exactly what a bad/good pair can teach.
            Attribution::Authored,
            // Declared, where it was absent — the same omission the invalid-index entry above
            // carried, and it reads the same way: a null class in this artifact does not mean
            // "unset", it means the rule classifies no downtime at all. `NotValidConstraintCheck`
            // emits `online` on every finding, so the artifact was stating the opposite of the code.
            DowntimeClass::Online,
        );
    }

    private static function invalidIndex(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.INVALID_INDEX',
            // ⚠️ MEDIUM, NOT HIGH, AND THE CATALOG SAID HIGH WHILE THE CHECK EMITTED MEDIUM.
            // `InvalidIndexCheck` carries the reasoning for both halves and gets them right: the
            // plain finding is debt somebody can carry another week, so it is `medium`, and HIGH
            // belongs to its sibling `DEPLOY.LEGACY.INVALID_INDEX_NAME_COLLISION`, where the deploy
            // is certain to fail. The catalog had taken the louder of the two for both.
            //
            // A consumer reads severity from this artifact — it is what the MCP tool serves and
            // what a project scoring its backlog sorts on — so the two disagreeing means one of
            // them is lying about every finding of this rule.
            Severity::Medium,
            self::deploy(),
            [
                'reports debt from an EARLIER deploy: an index left invalid by a build that did not '
                .'finish, which the planner ignores while it still costs write amplification',
                'cannot tell an index that is mid-build from one whose build failed — both are '
                .'`indisvalid = false` while they exist',
            ],
            Attribution::Observed,
            // Declared, where it was absent. A null class is not "unset" in this artifact: the
            // record's own docblock says a null pair means "classifies no downtime whatsoever",
            // which was a statement about this rule that its own findings contradicted. Every
            // finding it emits carries `online` — the invalid index locks nothing and slows
            // nothing; what it does is make a later deploy FAIL, which is a different fact and
            // belongs to severity rather than to this axis.
            DowntimeClass::Online,
        );
    }

    private static function orphanTransitionObject(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT',
            // Low, and the axis earns it: this is housekeeping that has waited months already, not
            // something a deploy is blocked on. Reporting it beside findings that stop a release
            // would teach a reader to discount both.
            Severity::Low,
            self::deploy(),
            [
                'reads NAMES, which is a heuristic and never evidence: `orders_old` is what an '
                .'abandoned rename leaves behind and what a team calls the archive it queries every '
                .'quarter, and the catalog holds nothing that separates them — so every match is '
                .'reported as undetermined and never as a failure',
                'cannot tell a leftover from an object somebody meant to keep; what would settle it '
                .'is the object appearing in no migration state at all, which is a separate reading',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    private static function oscArtifact(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.OSC_ARTIFACT',
            // Low is the TABLE case; the trigger finding raises itself to Medium at the site,
            // because a leftover table costs storage and a leftover trigger costs every write on a
            // live table. The catalog carries the floor.
            Severity::Low,
            self::deploy(),
            [
                'reads names an online-schema-change tool GENERATES — gh-ost, pt-osc and InnoDB each '
                .'to its own documented scheme — which is a narrower claim than a suffix hunt but '
                .'still a name rather than a state',
                'cannot tell a run that DIED from one still in flight: gh-ost works in `_t_gho` for '
                .'hours, and reporting that as wreckage would call the healthy case the broken one',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    private static function unenforcedConstraint(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.CONSTRAINT_NOT_ENFORCED',
            Severity::Medium,
            self::deploy(),
            [
                'reads a FACT the catalog states outright — `ENFORCED = NO` — so unlike the two '
                .'name-based checks beside it this one FAILS rather than reporting undetermined; '
                .'there is no second reading needed and no in-flight state that looks the same',
                'says nothing about WHY the constraint is unenforced or how long it has been. The '
                .'likely answer is that the data did not satisfy it, which makes turning it back on '
                .'a data decision rather than a schema one — and makes the age a question for the '
                .'debt reconciliation rather than for this reading',
            ],
            // AUTHORED, the MySQL sibling of the row above and the second of two. `ENFORCED = NO`
            // is a fact the catalog states outright rather than a name this check guessed at, and a
            // migration put it there — so the pair is about the reader's own text.
            Attribution::Authored,
            DowntimeClass::Online,
        );
    }

    private static function diskHeadroom(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.PREFLIGHT.DISK_HEADROOM',
            Severity::High,
            self::deploy(),
            [
                'an ESTIMATE from current object sizes, never a measurement: what a rewrite actually '
                .'writes depends on fill factor, TOAST, index rebuilds and the WAL it generates',
                'reads what the instance reports about its own storage; on a managed platform that '
                .'figure can be a quota rather than a disk, and an autoscaling volume makes it a '
                .'moving target',
            ],
            Attribution::Observed,
            DowntimeClass::Rewrite,
        );
    }

    private static function inactiveReplicationSlot(): DeployCheckMetadata
    {
        return DeployCheckMetadata::derived(
            'DEPLOY.PREFLIGHT.INACTIVE_REPLICATION_SLOT',
            self::deploy(),
            [
                'the severity rises with how far the slot has fallen behind, so the catalog names '
                .'none — the finding carries the one that fits what was read',
                'an inactive slot is not always abandoned: a replica that is down for maintenance '
                .'looks identical to one that will never return, and only a human knows which',
            ],
            Attribution::Observed,
        );
    }

    private static function lockBlocker(): DeployCheckMetadata
    {
        return DeployCheckMetadata::derived(
            'DEPLOY.PREFLIGHT.LOCK_BLOCKER',
            self::deploy(),
            [
                'a snapshot: a session holding a lock now may release it before the migration asks '
                .'for one, and one that is idle now may take a lock a second later',
                'the severity depends on what the blocking session is doing, so the catalog names '
                .'none',
                'sees the relations the migration NAMES; a lock taken on a relation reached '
                .'indirectly — through a foreign key, a trigger, a view — is not anticipated here',
            ],
            Attribution::Observed,
        );
    }

    private static function metadataLockBlocker(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.PREFLIGHT.METADATA_LOCK_BLOCKER',
            Severity::High,
            self::deploy(),
            [
                'a snapshot, like its PostgreSQL counterpart: the blocking session may be gone by the '
                .'time the migration runs',
                'MySQL grants metadata locks in ORDER, so a single long transaction blocks both the '
                .'migration and every reader queued behind it — the finding is about the queue, not '
                .'only about the one session it names',
            ],
            Attribution::Observed,
            DowntimeClass::Blocking,
        );
    }

    private static function missingPrivilege(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.PREFLIGHT.MISSING_PRIVILEGE',
            Severity::Critical,
            self::deploy(),
            [
                'reports a privilege the migration will need and the role does not hold; it cannot '
                .'see a privilege granted through a role membership the catalog does not expose',
                'Critical because the migration will not run at all — this is the one finding in the '
                .'family that is about a deploy that cannot start rather than one that should not',
            ],
            Attribution::Observed,
            DowntimeClass::Blocking,
        );
    }

    /**
     * Missing OWNERSHIP, which PostgreSQL does not let anybody grant.
     *
     * Its own row rather than a note under the privilege check, because the two send a reader to
     * different actions: one runs a `GRANT`, the other transfers ownership or runs the migration as
     * the owner. Reporting both under one id let somebody read "missing privilege", run the `GRANT`
     * it named, and watch the next deploy fail identically.
     */
    private static function ownershipMissing(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.CONTEXT.GRANT.OWNERSHIP_MISSING',
            Severity::Critical,
            self::deploy(),
            [
                'asks `pg_has_role(role, relowner, \'USAGE\')`, so ownership held through a role '
                .'membership counts — but ownership acquired between this check and the migration '
                .'does not, because the answer describes the moment it looked',
                'Critical for the same reason as its privilege sibling: the migration stops halfway, '
                .'leaving the schema partly applied while the application is already deployed against '
                .'the other half',
                'says nothing about an object the migration CREATES — that needs `CREATE` on the '
                .'schema, and an object that does not exist yet has no owner to compare against',
            ],
            Attribution::Observed,
            DowntimeClass::Blocking,
        );
    }

    /**
     * Wreckage from an earlier deploy that the NEXT one will collide with.
     *
     * Separate from the plain invalid-index row rather than a louder severity on it, because the two
     * are different decisions. An invalid index nobody is about to re-create is debt: real, worth
     * clearing, survivable for another week. One whose name a pending `CREATE INDEX` re-uses is a
     * deploy that ends halfway with an error nobody reads as a name conflict.
     */
    private static function invalidIndexNameCollision(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.LEGACY.INVALID_INDEX_NAME_COLLISION',
            Severity::High,
            self::deploy(),
            [
                'matches on the index NAME the pending migration uses; a build that reaches the same '
                .'object under a different name collides at run time and is not anticipated here',
                'cannot tell an index that is mid-build from one whose build failed — both read '
                .'`indisvalid = false` while they exist, and only the second is wreckage',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * A concurrent index build waiting on transactions that have nothing to do with its table.
     *
     * Its own row because the mechanism surprises people: a concurrent index build waits for every
     * older transaction to finish, not only the ones touching its own relation. A long query in an
     * unrelated schema delays it just as effectively, and the build does not fail — it sits there.
     */
    private static function concurrentlyBlocker(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.PREFLIGHT.CONCURRENT_INDEX_BLOCKER',
            Severity::Medium,
            self::deploy(),
            [
                'a snapshot: a session running now may finish before the build starts waiting, and '
                .'one that is idle now may open a transaction a second later',
                'Medium rather than High because nothing breaks — the build waits, holding a SHARE '
                .'UPDATE EXCLUSIVE lock, for as long as the oldest transaction lives',
                'counts sessions past the activity reader\'s threshold on ANY table, so it cannot say '
                .'which of them the build will actually end up waiting for',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }

    /**
     * The escalation could not read the object a finding names.
     *
     * A statement about the INSTANCE, which is why it carries a `DEPLOY.PREFLIGHT.*` id rather than
     * anything in the lint namespace: putting it there would create an id that only exists when a
     * database happens to be reachable.
     *
     * `derived` because the finding is `undetermined` and carries no severity at all — a fixed one
     * here would put a number on a check that did not answer.
     */
    private static function statisticsUnread(): DeployCheckMetadata
    {
        return DeployCheckMetadata::derived(
            'DEPLOY.PREFLIGHT.STATISTICS_UNREAD',
            self::deploy(),
            [
                'reports that an object\'s statistics could not be read, never that the object is '
                .'small or large — the un-escalated verdict lint already produced stands',
                'the failure direction is "no escalation", never a wrong severity: the escalator only '
                .'ever raises, so a reading it could not make leaves the honest answer in place',
            ],
            Attribution::Observed,
        );
    }

    private static function replicationLag(): DeployCheckMetadata
    {
        return DeployCheckMetadata::fixed(
            'DEPLOY.PREFLIGHT.REPLICATION_LAG',
            Severity::Info,
            self::deploy(),
            [
                'lag is read from the primary\'s view of its replicas; a replica the primary does not '
                .'know about is invisible',
                'Info rather than a warning: what lag is acceptable depends on what the application '
                .'does with its replicas, which this package cannot know',
            ],
            Attribution::Observed,
            DowntimeClass::Online,
        );
    }
}
