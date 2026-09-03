<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\OnlineSchemaChangeArtifacts;
use Pushery\SQLens\Deploy\PostdeployContext;
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
 * What an online-schema-change tool left behind, read once after the deploy.
 *
 * MySQL is the engine where these tools live, and the leftovers they produce are the most
 * recognizable in either database — not because they are obvious but because they are GENERATED. A
 * person does not write `_users_gho` or `#sql-1234_a`; gh-ost, pt-online-schema-change and InnoDB
 * do, each to its own documented scheme.
 *
 * ## Why the trigger half is not decoration
 *
 * A leftover TABLE costs storage and backup time — real, and payable at leisure. A leftover
 * pt-osc TRIGGER costs every `INSERT`, `UPDATE` and `DELETE` on the REAL table, forever, and writes
 * into a table nobody reads. That is the one on this list somebody should act on today, so it is
 * reported with its own sentence rather than folded into "an artifact was found".
 *
 * ## Still `undetermined`, and for a different reason than its PostgreSQL sibling
 *
 * The sibling is undetermined because a NAME is not evidence. Here the name genuinely is a tool's
 * output — but a run IN FLIGHT looks exactly like one that died. gh-ost creates `_t_gho` and works
 * in it for hours; catching that mid-migration and calling it wreckage reports the healthy case as
 * the broken one, which is the more expensive of the two mistakes.
 *
 * ## Primum non nocere
 *
 * Reports; never drops. A `#sql-` table in particular is one InnoDB may still be using, and the
 * message says so rather than leaving the reader to find out.
 */
final readonly class OrphanTransitionObjectCheck implements PostdeployCheck
{
    public const string ID = 'DEPLOY.LEGACY.OSC_ARTIFACT';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
    }

    #[RawSql(reason: 'reads information_schema.TABLES and TRIGGERS for names an online-schema-change tool generates; these artifacts have no other representation')]
    public function run(PostdeployContext $context): CheckResult
    {
        try {
            $tables = $context->session->read(static fn (Connection $db): array => $db->select(
                'select TABLE_SCHEMA as schema_name, TABLE_NAME as object_name'
                .' from information_schema.TABLES'
                .' where TABLE_SCHEMA not in (\'mysql\', \'information_schema\', \'performance_schema\', \'sys\')'
                .' order by TABLE_SCHEMA, TABLE_NAME',
            ));

            $triggers = $context->session->read(static fn (Connection $db): array => $db->select(
                'select TRIGGER_SCHEMA as schema_name, TRIGGER_NAME as object_name,'
                .' EVENT_OBJECT_TABLE as on_table'
                .' from information_schema.TRIGGERS'
                .' where TRIGGER_SCHEMA not in (\'mysql\', \'information_schema\', \'performance_schema\', \'sys\')'
                .' order by TRIGGER_SCHEMA, TRIGGER_NAME',
            ));
        } catch (Throwable $failure) {
            // Undetermined, never a pass — and on MySQL this branch is the ORDINARY case rather than
            // the exotic one. `information_schema` is filtered by privilege without a word, so an
            // under-privileged read succeeds and comes back empty; a read that FAILS is the honest
            // half of that, and collapsing it into "nothing found" would be the same silent green
            // the privilege probe exists to prevent.
            return CheckResult::undetermined(
                self::ID,
                'information_schema could not be read, so whether an online-schema-change tool left '
                .'artifacts behind is unknown: '.$failure->getMessage(),
            );
        }

        $findings = [];

        foreach (array_map(static fn (mixed $row): object => (object) $row, $tables) as $row) {
            $name = $this->text($row, 'object_name');

            if ($name !== '' && OnlineSchemaChangeArtifacts::isTable($name)) {
                $findings[] = $this->tableFinding($context, $this->text($row, 'schema_name'), $name);
            }
        }

        foreach (array_map(static fn (mixed $row): object => (object) $row, $triggers) as $row) {
            $name = $this->text($row, 'object_name');

            if ($name !== '' && OnlineSchemaChangeArtifacts::isTrigger($name)) {
                $findings[] = $this->triggerFinding(
                    $context,
                    $this->text($row, 'schema_name'),
                    $name,
                    $this->text($row, 'on_table'),
                );
            }
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::undetermined(
                self::ID,
                sprintf(
                    '%d online-schema-change artifact(s) are present. A run still IN FLIGHT looks '
                    .'exactly like one that died, so this is reported rather than decided.',
                    count($findings),
                ),
                $findings,
            );
    }

    private function tableFinding(PostdeployContext $context, string $schema, string $name): Finding
    {
        $qualified = $schema === '' ? $name : $schema.'.'.$name;
        $tool = OnlineSchemaChangeArtifacts::toolFor($name);

        return Finding::undetermined(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The table `%s` is an artifact %s generates — no project writes a name in that '
                .'scheme by hand. If the run that made it finished, it is dead weight: storage and '
                .'backup time paid for indefinitely. If a run is STILL IN FLIGHT it is doing its '
                .'job, and the two look identical from here, which is why this is reported and not '
                .'decided. Confirm nothing is running, then remove it in a change of its own — '
                .'`DROP TABLE %s;` — as a proposal rather than an instruction: a drop cannot be '
                .'undone and SQLens never runs one. A `#sql-` table in particular may be one InnoDB '
                .'is using right now.',
                $qualified,
                $tool,
                $qualified,
            ),
            reason: UndeterminedReason::NameSuggestsTransitionObject,
            location: Location::inCatalog($context->driver, $context->connection, $qualified, SchemaObjectType::Table),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Low,
        )->withDowntimeClass(DowntimeClass::Online);
    }

    private function triggerFinding(PostdeployContext $context, string $schema, string $name, string $onTable): Finding
    {
        $qualified = $schema === '' ? $name : $schema.'.'.$name;

        return Finding::undetermined(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The trigger `%s` on `%s` is one pt-online-schema-change installs to keep its copy '
                .'in step. Left behind, it is not dead weight — it fires on every INSERT, UPDATE and '
                .'DELETE on `%s` for as long as it exists, writing into a table nothing reads. Of '
                .'everything this check reports, it is the one to look at today. Confirm no run is '
                .'in flight, then `DROP TRIGGER %s;` — a proposal, not an instruction, and SQLens '
                .'never runs one.',
                $qualified,
                $onTable === '' ? 'its table' : $onTable,
                $onTable === '' ? 'that table' : $onTable,
                $qualified,
            ),
            reason: UndeterminedReason::NameSuggestsTransitionObject,
            location: Location::inCatalog($context->driver, $context->connection, $qualified, SchemaObjectType::Trigger),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Medium rather than Low, and the axis earns it: a leftover TABLE costs storage, a
            // leftover TRIGGER costs every write on a live table. Same artifact class, different
            // bill, and reporting them alike would bury the one that is still being paid.
            severity: Severity::Medium,
        )->withDowntimeClass(DowntimeClass::Online);
    }

    /** A column of a driver row as a string — the same normalization every catalog check here makes. */
    private function text(object $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }
}
