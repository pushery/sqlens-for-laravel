<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
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
 * Indexes left behind by a `CREATE INDEX CONCURRENTLY` that did not finish.
 *
 * A concurrent build that is canceled, killed, or lost with its session leaves the index in the
 * catalog marked invalid. It is not used by any query — so it helps nobody — and it is still
 * maintained on every write, so it costs on every INSERT and UPDATE. That combination is why it
 * survives: nothing is broken, and nothing points at it.
 *
 * ## Why this belongs to the deploy gate rather than to `audit`
 *
 * The audit suite would report it as a schema problem, which it is. The deploy gate reports it as a
 * problem about to become an ERROR, which is a different urgency: the migration that was interrupted
 * is usually the one about to be re-run, and `CREATE INDEX` refuses a name that already exists —
 * invalid or not. So the second run fails on a name conflict, halfway through a deploy, for a reason
 * that reads like a bug in the migration.
 *
 * ## Why nothing is dropped
 *
 * The finding carries the safe sequence and stops there. Dropping an index is a schema change, and
 * this command is the one that promises never to make one. `DROP INDEX CONCURRENTLY` is also not
 * unconditionally safe to automate — it takes a `SHARE UPDATE EXCLUSIVE` lock and cannot run inside
 * a transaction block, which is a decision for whoever owns the deploy window.
 *
 * ## Catalog dirt this deliberately excludes
 *
 * Extension-owned indexes are skipped: they belong to the extension's own migration story and a
 * project cannot act on them. Partition children are skipped in favor of their parent, because
 * reporting a hundred identical findings for one partitioned table teaches a reader to skim.
 *
 * @see https://www.postgresql.org/docs/18/sql-createindex.html
 */
final readonly class InvalidIndexCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.LEGACY.INVALID_INDEX';

    /**
     * The word this debt is filed under, held here because this class owns the catalog query.
     *
     * A constant rather than a literal for the reason the constraint family already learned: a
     * second spelling would be a second debt for one index, and the ledger's identity is derived
     * from the kind. The postdeploy adapter reads it from here rather than writing it again.
     */
    public const string DEBT_KIND = 'invalid_index';

    /**
     * The same wreckage, but the deploy about to run WILL fail on it.
     *
     * A separate id rather than a louder severity on the first, because the two call for different
     * decisions. An invalid index nobody is about to re-create is debt: real, worth clearing,
     * survivable for another week. One whose name a pending `CREATE INDEX` re-uses is a deploy that
     * ends halfway through with an error nobody will read as a name conflict — and that is not a
     * matter of degree.
     */
    public const string COLLISION_ID = 'DEPLOY.LEGACY.INVALID_INDEX_NAME_COLLISION';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        // PostgreSQL only, and it has no MySQL counterpart to write: InnoDB's online index build is
        // not a separate catalog state, so there is nothing left behind to find. The runner asks
        // this before running anything, so on MySQL the check produces NO result rather than a
        // fourth outcome value.
        return $driver === 'pgsql';
    }

    #[RawSql(reason: 'reads pg_index.indisvalid; an invalid index left by a failed CONCURRENTLY build is a catalog fact with no other representation')]
    public function run(PreflightContext $context): CheckResult
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select n.nspname as schema_name, c.relname as index_name, t.relname as table_name,'
                .' i.indisready as is_ready'
                .' from pg_index i'
                .' join pg_class c on c.oid = i.indexrelid'
                .' join pg_class t on t.oid = i.indrelid'
                .' join pg_namespace n on n.oid = c.relnamespace'
                // Extension-owned objects belong to the extension's migration story, and a project
                // cannot act on them — reporting one is asking somebody to fix what they do not own.
                .' where not exists ('
                .'   select 1 from pg_depend d'
                .'   where d.objid = c.oid and d.classid = \'pg_class\'::regclass and d.deptype = \'e\''
                .' )'
                // A partition child is reported through its parent. A hundred identical findings for
                // one partitioned table is the shape that teaches a reader to skim the report.
                .' and not exists ('
                .'   select 1 from pg_inherits h where h.inhrelid = c.oid'
                .' )'
                .' and i.indisvalid = false'
                .' order by n.nspname, t.relname, c.relname',
            ));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'the index catalog could not be read, so whether a previous concurrent build left '
                .'something behind is unknown — and the deploy about to run is the one that would '
                .'collide with it: '.$failure->getMessage(),
            );
        }

        $findings = [];

        // Normalized rather than guarded. A `! is_object($row)` branch here read as defensive and
        // was unreachable — the driver answers with objects, every time, and the coverage gate said
        // so by never entering it. A cast states the same requirement without a line nothing can
        // execute, and an unexecutable guard is worse than none: it looks like a check somebody made.
        // The names the pending migrations will try to create, read ONCE rather than per row: the
        // set is the same for every index, and rebuilding it inside the loop would make a hundred
        // invalid indexes cost a hundred passes over the same statements.
        $pendingIndexNames = $this->pendingIndexNames($context);

        foreach (array_map(static fn (mixed $row): object => (object) $row, $rows) as $row) {
            $schema = $this->text($row, 'schema_name');
            $index = $this->text($row, 'index_name');

            $findings[] = $this->collides($pendingIndexNames, $schema, $index)
                ? $this->collisionFinding($context, $schema, $index, $this->text($row, 'table_name'))
                : $this->finding(
                    $context,
                    $schema,
                    $index,
                    $this->text($row, 'table_name'),
                    // `indisready = false` says the build never even reached the point of tracking
                    // new rows, so it is the earlier and more clearly dead of the two states.
                    // Reported as part of the message rather than as a second finding id: the action
                    // is identical, and two ids for one action is a distinction a reader looks up.
                    ($row->is_ready ?? true) === false,
                );
        }

        // Nothing found is a clean PASS, not a skip. The distinction matters here more than usual:
        // this check answers "is there wreckage from last time", and a skip would leave that
        // question open on exactly the run that could have closed it.
        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /**
     * Every index name the pending migrations will try to create, canonical.
     *
     * Both spellings are kept for each one, and the reason is a real asymmetry rather than caution.
     * `CREATE INDEX idx ON public.orders (...)` names the index WITHOUT a schema — PostgreSQL puts
     * it in the table's — while the catalog reports it back as `public.idx`. Comparing only the
     * qualified form would miss every unqualified statement, which is most of them; comparing only
     * the bare name would call a collision on `other_schema.idx`, which is a different index.
     *
     * @return list<string>
     */
    private function pendingIndexNames(PreflightContext $context): array
    {
        $names = [];

        foreach ($context->pending->statements as $statement) {
            if (! in_array($statement->statementKind, [
                StatementKind::CreateIndex,
                StatementKind::CreateFulltextIndex,
                StatementKind::CreateSpatialIndex,
            ], true)) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                if ($target->type === SchemaObjectType::Index) {
                    $names[] = $target->qualifiedName();
                }
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Whether a pending statement re-creates this exact index name.
     *
     * @param  list<string>  $pendingIndexNames
     */
    private function collides(array $pendingIndexNames, string $schema, string $index): bool
    {
        // The qualified form matches a statement that named a schema; the bare form matches one that
        // did not, which then lands in the table's schema — the same schema this row came from.
        return in_array($schema.'.'.$index, $pendingIndexNames, true)
            || in_array($index, $pendingIndexNames, true);
    }

    /** The louder finding: this deploy will stop here. */
    private function collisionFinding(PreflightContext $context, string $schema, string $index, string $table): Finding
    {
        $qualified = $schema === '' ? $index : $schema.'.'.$index;

        return Finding::fail(
            ruleId: self::COLLISION_ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The index `%s` on `%s` is INVALID — left behind by a `CREATE INDEX CONCURRENTLY` '
                .'that did not finish — and a migration in THIS deploy creates an index by that same '
                .'name. `CREATE INDEX` refuses a name that already exists, invalid or not, so this '
                .'deploy will stop at that statement with an error that reads like a bug in the '
                .'migration. Drop the leftover first: `DROP INDEX CONCURRENTLY %s;` — outside a '
                .'transaction block, and it takes a SHARE UPDATE EXCLUSIVE lock, so it is a decision '
                .'for whoever owns the window. This command drops nothing itself.',
                $index,
                $table,
                $qualified,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $qualified, SchemaObjectType::Index),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::COLLISION_ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // High rather than Medium, and this is where the severity axis earns its keep: the plain
            // finding is debt somebody can carry another week, this one is a deploy that ends
            // halfway through. Same catalog state, different certainty.
            severity: Severity::High,
        )->withDowntimeClass(
            // Still `online`. The index locks nothing and slows nothing — what it does is make a
            // deploy FAIL, and calling that `blocking` would teach a reader to read the axis as
            // "how bad is this" instead of "what does it do to concurrent traffic".
            DowntimeClass::Online,
        );
    }

    /**
     * One column as a string.
     *
     * A driver may answer a name as a string or hand back something else entirely on a column it
     * did not recognize, and a bare cast on `mixed` is where an unhelpful conversion notice comes
     * from. Nothing is invented here: a value that is not a scalar becomes an empty string, which
     * the caller renders as an unqualified name rather than as a plausible wrong one.
     */
    private function text(object $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    private function finding(
        PreflightContext $context,
        string $schema,
        string $index,
        string $table,
        bool $neverReady,
    ): Finding {
        $qualified = $schema === '' ? $index : $schema.'.'.$index;

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The index `%s` on `%s` is INVALID — left behind by a `CREATE INDEX CONCURRENTLY` '
                .'that did not finish%s. No query uses it and every write still maintains it, which '
                .'is why it survives: nothing is broken and nothing points at it. It also blocks the '
                .'re-run, because `CREATE INDEX` refuses a name that already exists, invalid or not. '
                .'Drop it before the deploy: `DROP INDEX CONCURRENTLY %s;` — outside a transaction '
                .'block, and it takes a SHARE UPDATE EXCLUSIVE lock, so it is a decision for whoever '
                .'owns the window. This command drops nothing itself.',
                $index,
                $table,
                $neverReady ? ' (it never reached the point of tracking new rows)' : '',
                $qualified,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $qualified, SchemaObjectType::Index),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Medium rather than high on its own: an invalid index costs write throughput and is a
            // certain failure only when the deploy re-creates that exact name. The name-collision
            // branch is where that certainty gets its own, louder finding — and it needs the pending
            // migrations, which this command does not carry yet.
            severity: Severity::Medium,
        )->withDowntimeClass(
            // `online`, and the axis keeps meaning what it says: the invalid index locks nothing and
            // slows no deploy. What it does is make one FAIL, which is a different thing from making
            // it slow, and calling it `blocking` would teach a reader to discount the field.
            DowntimeClass::Online,
        );
    }
}
