<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Pedantic\ImplicitCast;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A foreign key whose two ends are not the same type.
 *
 * ## The reason is NOT the one everybody gives, and that was measured
 *
 * The usual argument is that a mismatched pair still compares but stops using the index. Against
 * PostgreSQL 18.4 that is false:
 *
 * ```
 * EXPLAIN SELECT * FROM k1 WHERE pid = 42::bigint;   -- pid is int, referencing a bigint
 *   ->  Index Scan using k1_pid_idx on k1
 *         Index Cond: (pid = '42'::bigint)
 * ```
 *
 * The btree integer operator family carries cross-type operators, so the index is used. A rule
 * built on the index argument would ship advice that is confident, specific and wrong.
 *
 * ## What is actually wrong is worse, and it is DATED
 *
 * An `int` column referencing a `bigint` key can only ever point at the first 2^31 of its target's
 * 2^63 values. Nothing about the schema says so. Every test passes, because a test database never
 * gets there. Then the parent sequence crosses 2,147,483,647 — years after the migration — and
 * every insert into the child fails with an out-of-range error naming a column nobody connects to a
 * foreign key.
 *
 * So this rule reports the NARROWING direction as the finding it is, and reports a widening or a
 * differing non-integer pair for what it is too: a conversion the schema did not intend.
 *
 * ## Audit only, and that is structural
 *
 * A migration adding a foreign key carries the type of NEITHER column — the types live in the
 * `CREATE TABLE` statements, and the referenced table is almost always created by a migration that
 * is no longer pending when this one runs. The catalog is the only place both ends exist at once.
 * A lint half would therefore answer `undetermined` for nearly every foreign key, which is noise
 * rather than honesty.
 */
final class TypeImplicitCastRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Pairs PostgreSQL stores identically, so comparing across them costs nothing.
     *
     * Measured rather than assumed — `pg_type` reports the same `typlen`, `typalign` and
     * `typstorage` for `text` and `varchar`. `bpchar` is deliberately NOT in the group: it pads to
     * its declared length, so comparing it against either of the others is a real conversion with a
     * real answer change.
     *
     * @var list<list<string>>
     */
    private const array EQUIVALENT = [
        ['text', 'varchar', 'character varying'],
    ];

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L9.TYPE_IMPLICIT_CAST';
    }

    public function level(): Level
    {
        return Level::Pedantic;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $offenders = [];
        $unread = [];

        foreach (ImplicitCast::pairs($object) as $pair) {
            if ($pair['localType'] === null || $pair['farType'] === null) {
                // One side unread. Not a pass: the question was asked and not answered, and the two
                // must not look alike — a schema whose catalog reading lost a column would
                // otherwise report every one of its foreign keys as fine.
                $unread[] = $pair['constraint'].' ('.$pair['local'].' → '.$pair['far'].')';

                continue;
            }

            if (ImplicitCast::sameType($pair['localType'], $pair['farType'], self::EQUIVALENT)) {
                continue;
            }

            $offenders[] = $this->sentence($pair);
        }

        if ($offenders !== []) {
            sort($offenders, SORT_STRING);

            return [RuleVerdict::flag(implode(' ', $offenders), $object->qualifiedName, $object->type)];
        }

        if ($unread !== []) {
            sort($unread, SORT_STRING);

            return [RuleVerdict::undetermined(
                'The type of at least one end of these foreign keys was not established, so whether the two sides '
                .'agree is unknown rather than fine: '.implode(', ', $unread).'.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        return [];
    }

    /** @param  array{constraint: string, local: string, localType: ?string, far: string, farType: ?string}  $pair */
    private function sentence(array $pair): string
    {
        $local = ImplicitCast::integerWidth((string) $pair['localType']);
        $far = ImplicitCast::integerWidth((string) $pair['farType']);

        if ($local !== null && $far !== null && $local < $far) {
            return sprintf(
                '`%s` is `%s` and references `%s`, which is `%s`. The narrower side can only ever point at the '
                .'first %s of the wider one\'s values, so this key stops working the day the referenced sequence '
                .'passes that number — long after the migration that set it up. Widen `%s` to `%s`.',
                $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
                number_format((2 ** ($local * 8 - 1)) - 1),
                $pair['local'], $pair['farType'],
            );
        }

        return sprintf(
            '`%s` is `%s` and references `%s`, which is `%s`. PostgreSQL compares them by converting one side, '
            .'which the schema did not ask for and nothing records. Declare both ends as the same type.',
            $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
        );
    }
}
