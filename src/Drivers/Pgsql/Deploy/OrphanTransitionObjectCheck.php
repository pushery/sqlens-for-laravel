<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Deploy\TransitionObjectPatterns;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Objects whose NAMES say they were meant to be temporary, read once after the deploy.
 *
 * An expand/contract migration that stopped halfway leaves `users_old`. A backfill helper leaves
 * `tmp_backfill_state`. A snapshot taken "just in case" leaves `orders_20260721`. Each of them
 * survives indefinitely, costs storage and backup time forever, and — the part that actually bites —
 * is the first thing somebody restores by mistake, because it looks like the real table with a
 * suffix.
 *
 * ## It NEVER fails, and that is the design rather than timidity
 *
 * A name is not evidence. `orders_old` is exactly what an abandoned rename leaves behind and exactly
 * what a team calls the archive it queries every quarter, and the catalog holds nothing that
 * separates the two. So every match is reported at the `undetermined` rung with
 * {@see UndeterminedReason::NameSuggestsTransitionObject}, and the message says what would settle it.
 *
 * The alternative was measured against the package's own history rather than imagined: a heuristic
 * that presents itself as certainty gets one false positive on a table people rely on, and that is
 * the last time anybody reads the report. `pass` would be worse still — it would hide real wreckage
 * behind a clean result.
 *
 * **What turns this into a decided answer is a second, independent reading**: the object appearing
 * in no migration state at all. That is the shadow-expectation comparison, and it is deliberately a
 * different check — this one owns the catalog reading and the name heuristic, and nothing else.
 *
 * ## Three exclusions, none of them this class's invention
 *
 * Extension-owned objects (`pg_depend`), partition children (`pg_inherits`) and the system schemas
 * are excluded in the query, the same three exclusions every other PostgreSQL catalog reading here
 * makes and for the same reasons: a project cannot act on what an extension owns, a hundred
 * identical findings for one partitioned table teaches a reader to skim, and `pg_catalog` is not
 * anybody's migration.
 *
 * ## Primum non nocere
 *
 * The remedy is a `DROP`, and a drop is irreversible. This check reports; it never runs one, and the
 * message says so in its own words rather than leaving it to the reader to assume.
 */
final readonly class OrphanTransitionObjectCheck implements PostdeployCheck
{
    public const string ID = 'DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT';

    public function __construct(private ?TransitionObjectPatterns $patterns = null) {}

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    #[RawSql(reason: 'reads pg_class and pg_namespace for object names; a leftover transition object is a catalog fact with no other representation')]
    public function run(PostdeployContext $context): CheckResult
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select n.nspname as schema_name, c.relname as object_name, c.relkind as kind'
                .' from pg_class c'
                .' join pg_namespace n on n.oid = c.relnamespace'
                // The kinds a migration creates and could leave behind. Indexes are absent on
                // purpose: an orphaned index is what the INVALID-index check answers, and two
                // checks reporting one object is the shape a reader learns to skim.
                .' where c.relkind in (\'r\', \'p\', \'v\', \'m\', \'S\')'
                .' and n.nspname not in (\'pg_catalog\', \'information_schema\')'
                .' and n.nspname not like \'pg_toast%\''
                .' and n.nspname not like \'pg_temp%\''
                .' and not exists ('
                .'   select 1 from pg_depend d'
                .'   where d.objid = c.oid and d.classid = \'pg_class\'::regclass and d.deptype = \'e\''
                .' )'
                .' and not exists ('
                .'   select 1 from pg_inherits h where h.inhrelid = c.oid'
                .' )'
                .' order by n.nspname, c.relname',
            ));
        } catch (Throwable $failure) {
            // Undetermined, never a pass. "No leftovers" and "the catalog could not be read" are the
            // two answers this check exists to keep apart, and a deploy that just finished is
            // exactly when somebody is deciding whether to look further.
            return CheckResult::undetermined(
                self::ID,
                'the relation catalog could not be read, so whether the deploy left transition '
                .'objects behind is unknown: '.$failure->getMessage(),
            );
        }

        $patterns = $this->patterns ?? TransitionObjectPatterns::shipped();
        $findings = [];

        foreach (array_map(static fn (mixed $row): object => (object) $row, $rows) as $row) {
            $schema = $this->text($row, 'schema_name');
            $name = $this->text($row, 'object_name');

            if ($name === '' || ! $patterns->matches($name)) {
                continue;
            }

            $findings[] = $this->finding($context, $schema, $name, $this->text($row, 'kind'));
        }

        // A pattern match is never a failure, so a non-empty result is still `undetermined` — the
        // rung is a property of what a name can prove, not of how many names matched.
        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::undetermined(
                self::ID,
                sprintf(
                    '%d object(s) carry a name that looks like a transition leftover. A name is not '
                    .'evidence, so this is reported rather than decided.',
                    count($findings),
                ),
                $findings,
            );
    }

    /** A column of a driver row as a string — the same normalization every catalog check here makes. */
    private function text(object $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    private function finding(PostdeployContext $context, string $schema, string $name, string $kind): Finding
    {
        $qualified = $schema === '' ? $name : $schema.'.'.$name;
        $type = $this->objectType($kind);

        return Finding::undetermined(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The %s `%s` carries a name that an unfinished expand/contract migration leaves '
                .'behind — a rename that was never completed, a backfill helper, a snapshot taken '
                .'just in case. It may equally be something you meant to keep: the catalog holds '
                .'nothing that tells the two apart, which is why this is reported and not decided. '
                .'If it is a leftover, remove it in a migration of its own — `DROP %s %s;` — and '
                .'read it as a proposal rather than an instruction, because a drop cannot be '
                .'undone and SQLens never runs one. If it is not, add it to the exclude file so '
                .'this stays quiet.',
                $this->objectWord($kind),
                $qualified,
                strtoupper($this->objectWord($kind)),
                $qualified,
            ),
            reason: UndeterminedReason::NameSuggestsTransitionObject,
            location: Location::inCatalog($context->driver, $context->connection, $qualified, $type),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Low, and the axis says why: this is housekeeping that has waited months already, not
            // something a deploy is blocked on. Reporting it higher would put it beside findings that
            // stop a release, and the reader would learn to discount both.
            severity: Severity::Low,
        )->withDowntimeClass(
            // Online: nothing here holds a lock or rewrites anything. The object exists and does
            // nothing, which is the entire complaint.
            DowntimeClass::Online,
        );
    }

    /** `relkind` as the word a person would use, for the message and the DROP it proposes. */
    private function objectWord(string $kind): string
    {
        return match ($kind) {
            'v' => 'view',
            'm' => 'materialized view',
            'S' => 'sequence',
            default => 'table',
        };
    }

    private function objectType(string $kind): SchemaObjectType
    {
        return match ($kind) {
            'v' => SchemaObjectType::View,
            'm' => SchemaObjectType::MaterializedView,
            'S' => SchemaObjectType::Sequence,
            default => SchemaObjectType::Table,
        };
    }
}
