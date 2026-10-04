<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Canonical\StatementAction;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\TargetRole;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * What the migration role must be allowed to do, derived from the pending statements.
 *
 * Every grant check needs this and none of them should compute it: three derivations of one question
 * are three chances to disagree, and the one that drifted would decide whichever check read it.
 *
 * ## It reads the capture and nothing else
 *
 * No database, no locks, no second parse. The statements already carry their kind and their targets
 * — the classification this run produced — so this is a mapping, not an analysis. Parsing the SQL
 * here would be a second opinion that can contradict the report printed beside it.
 *
 * ## Why an unrecognized statement produces a requirement rather than nothing
 *
 * Silence and "needs no privilege" are the same value in a list. A statement whose kind this build
 * cannot resolve therefore produces a requirement with a NAMED reason and no class, so a check
 * downstream reports `undetermined` instead of certifying a role it never tested against that
 * object.
 */
final readonly class RequiredPrivileges
{
    /**
     * How a statement kind maps onto what the role must be allowed to do.
     *
     * `Ownership` rather than `Alter` for every in-place change, and that is the decision this map
     * exists to record: on PostgreSQL `ALTER TABLE` cannot be granted at all. Filing it as a
     * privilege would let a check advise "grant ALTER on that table" — advice nobody can follow,
     * delivered inside a deploy window.
     */
    private const array BY_KIND = [
        'create_table' => PrivilegeClass::Create,
        'create_index' => PrivilegeClass::Create,
        'create_fulltext_index' => PrivilegeClass::Create,
        'create_spatial_index' => PrivilegeClass::Create,
        'drop_table' => PrivilegeClass::Drop,
        'drop_index' => PrivilegeClass::Drop,
        // A schema drop needs OWNERSHIP of the schema, not a grant — PostgreSQL does not make
        // `DROP` grantable. Classed as Drop rather than Ownership for the same reason `drop_table`
        // is: the two classes exist so a project can be told WHICH of them it is short of, and the
        // check asks the ownership question for both.
        'drop_schema' => PrivilegeClass::Drop,
        'truncate_table' => PrivilegeClass::Drop,
        'alter_table' => PrivilegeClass::Ownership,
        'add_column' => PrivilegeClass::Ownership,
        'alter_column' => PrivilegeClass::Ownership,
        'drop_column' => PrivilegeClass::Ownership,
        'add_constraint' => PrivilegeClass::Ownership,
        'add_primary_key' => PrivilegeClass::Ownership,
        'drop_constraint' => PrivilegeClass::Ownership,
        'rename' => PrivilegeClass::Ownership,
        // The ALTERED table's need. The referenced side is no longer decided here — it is decided
        // per target from the role, because this one kind names objects with two different needs
        // and a single class per statement necessarily gets one of them wrong.
        'add_foreign_key' => PrivilegeClass::Ownership,
        'dml' => PrivilegeClass::Write,
    ];

    /**
     * The requirements this pending set implies, deduplicated and deterministically ordered.
     *
     * @return list<PrivilegeRequirement>
     */
    public static function forPending(PendingWork $pending): array
    {
        $requirements = [];

        foreach ($pending->statements as $statement) {
            // The statement's own classification is its first action. Each later action of an
            // `ALTER TABLE` list asks for rights of its own: a foreign key behind an `ADD COLUMN`
            // needs REFERENCES on its parent as one alone does.
            $actions = [
                [$statement->statementKind, $statement->targets ?? []],
                ...array_map(static fn (StatementAction $action): array => [$action->kind, $action->targets], $statement->actions),
            ];

            foreach ($actions as [$kind, $targets]) {
                if ($targets === []) {
                    // No target means no object to ask about — and that is exactly the state that must
                    // not vanish. A raw `DO $$ … $$` or a driver-specific form the classifier does not
                    // know reaches here, and reporting nothing would tell a check the migration touches
                    // nothing at all.
                    $requirements[] = PrivilegeRequirement::underivable(
                        '(unresolved)',
                        SchemaObjectType::Table,
                        'privilege_requirement_underivable: this statement names no object this build '
                        .'could resolve, so what the role must be allowed to do could not be derived. '
                        .'It is reported rather than dropped, because an object nobody classified must '
                        .'not look like an object that needs nothing.',
                    );

                    continue;
                }

                // Read once, outside the loop over targets: the kind belongs to the ACTION, and
                // recomputing it per target invites the two to drift the day one of them grows a case.
                $class = $kind instanceof StatementKind ? self::BY_KIND[$kind->value] ?? null : null;
                $kindLabel = $kind instanceof StatementKind ? $kind->value : '(unclassified)';

                foreach ($targets as $target) {

                    // Per TARGET, not per statement. A foreign key names three objects with two
                    // different needs: ownership of the table being altered, and only REFERENCES on the
                    // one being pointed at. A role very often has exactly that split.
                    //
                    // Measured, and both engines were wrong in opposite directions: PostgreSQL
                    // classifies the statement as `add_constraint` and demanded ownership of the
                    // referenced table — failing a deploy that would have worked — while MySQL
                    // classifies it as `add_foreign_key` and demanded only REFERENCES on the altered
                    // one, which lets a predeploy check pass a deploy that then fails.
                    //
                    // The same holds for an index: it is built ON a table that already exists, and that
                    // is a right on the table, not a CREATE in its schema. Measured with the product's own
                    // capture: on PostgreSQL a role that may create in the schema but does not own the
                    // table passed this check and then failed at `must be owner of table`; on MySQL a user
                    // with ALTER on the table was refused for lacking CREATE, and one with CREATE alone
                    // passed and failed at `ALTER command denied`.
                    $targetClass = match (true) {
                        $target->role === TargetRole::Referenced => PrivilegeClass::References,
                        $target->type === SchemaObjectType::Table && self::buildsAnIndex($kind) => self::indexedTableClass($statement),
                        default => $class,
                    };

                    $requirements[] = $targetClass instanceof PrivilegeClass
                        ? PrivilegeRequirement::of($target->qualifiedName(), $target->type, $targetClass)
                        : PrivilegeRequirement::underivable(
                            $target->qualifiedName(),
                            $target->type,
                            sprintf(
                                'privilege_requirement_underivable: this build has no privilege mapping '
                                .'for statement kind `%s`, so what the role must be allowed to do on this '
                                .'object is unknown — which is not the same as needing nothing.',
                                $kindLabel,
                            ),
                        );
                }
            }
        }

        return self::deduplicated($requirements);
    }

    /** Whether the statement builds an index, which names the existing table it is built on. */
    private static function buildsAnIndex(?StatementKind $kind): bool
    {
        return in_array($kind, [StatementKind::CreateIndex, StatementKind::CreateFulltextIndex, StatementKind::CreateSpatialIndex], true);
    }

    /**
     * The right an index needs on its table, read from how the statement adds it.
     *
     * `ALTER TABLE … ADD INDEX`, the form Laravel writes on MySQL, is an alteration of the table on
     * every engine, so it is ownership (`ALTER` on MySQL). `CREATE INDEX` is its own right: the owner
     * on PostgreSQL, `INDEX` on MySQL. Measured on MySQL: a user holding INDEX alone runs the second
     * and is refused the first, and a user holding ALTER alone the other way round.
     */
    private static function indexedTableClass(CapturedStatement $statement): PrivilegeClass
    {
        return preg_match('/^\s*ALTER\s/i', (string) $statement->canonicalSql) === 1 ? PrivilegeClass::Ownership : PrivilegeClass::Index;
    }

    /**
     * @param  list<PrivilegeRequirement>  $requirements
     * @return list<PrivilegeRequirement>
     */
    private static function deduplicated(array $requirements): array
    {
        $byKey = [];

        foreach ($requirements as $requirement) {
            $byKey[$requirement->sortKey()] = $requirement;
        }

        // Sorted by the key rather than left in statement order: two runs over an unchanged set of
        // migrations must produce byte-identical output, and statement order is a fact about how
        // somebody wrote the migration rather than about what it needs.
        ksort($byKey);

        return array_values($byKey);
    }
}
