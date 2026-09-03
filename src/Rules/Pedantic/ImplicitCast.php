<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Pedantic;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The two ends of a foreign key, and whether they are the same type.
 *
 * ## What was measured, and what it corrected
 *
 * The premise this was built from said a mismatched pair "still compares, but stops using the
 * index". Measured against PostgreSQL 18.4, that is **false** for integer widths:
 *
 * ```
 * CREATE TABLE k1 (pid int REFERENCES p_big(id));   -- p_big.id is bigint
 * EXPLAIN SELECT * FROM k1 WHERE pid = 42::bigint;
 *   ->  Index Scan using k1_pid_idx on k1
 *         Index Cond: (pid = '42'::bigint)
 * ```
 *
 * PostgreSQL's btree integer operator family carries cross-type operators, so the index is used.
 * Building a rule on the index argument would have shipped advice that is confident, specific and
 * wrong — the failure mode this package treats as worse than no advice.
 *
 * **What IS true on PostgreSQL is worse, and it is dated.** A `bigint` key referenced by an `int`
 * column can only ever be pointed at for the first 2^31 of its 2^63 values. The schema compiles,
 * every test passes, and the day the parent sequence crosses 2,147,483,647 every insert into the
 * child fails — years after the migration, with nothing linking the two.
 *
 * **On MySQL the same pair does not exist.** Measured against 8.4.10, `int` referencing `bigint`
 * — signed or unsigned — is refused outright:
 *
 * ```
 * ERROR 3780 (HY000): Referencing column 'pid' and referenced column 'id'
 *                     in foreign key constraint 'k1_ibfk_1' are incompatible.
 * ```
 *
 * So what survives into a MySQL catalog and still differs is a pair the server ACCEPTED and
 * converts at runtime — `timestamp` against `datetime`, `varchar` against `char` — both measured as
 * created without complaint. Two engines, two different findings, one shared reading.
 *
 * ## Why the comparison is the BASE type and not the declared one
 *
 * `varchar(50)` referencing `varchar(100)` is created by both engines and costs nothing: same
 * storage, same comparison, no conversion. A rule comparing declared types would report it, and it
 * is the single most common shape in a real schema. The length is not a cast.
 */
final readonly class ImplicitCast
{
    /**
     * Every foreign-key column pair this table carries, as `[local, localType, far, farType]`.
     *
     * A type is `null` when the reading did not establish it — which the caller must report as
     * undetermined rather than as agreement. That distinction is the whole reason the projection
     * encodes a bare name differently from a `name=type` one.
     *
     * @return list<array{constraint: string, local: string, localType: ?string, far: string, farType: ?string}>
     */
    public static function pairs(SchemaObject $object): array
    {
        $pairs = [];

        foreach (ForeignKeyIndexCoverage::parse($object->getString('foreign_key_types') ?? '') as $edge => $sides) {
            if (count($sides) !== 2) {
                continue;
            }

            [$local, $far] = $sides;
            $constraint = self::constraintOf($edge);

            $pairs[] = [
                'constraint' => $constraint,
                'local' => self::nameOf($local),
                'localType' => self::valueOf($local),
                'far' => self::nameOf($far),
                'farType' => self::valueOf($far),
            ];
        }

        return $pairs;
    }

    /**
     * Whether two type names are the same type under a driver's equivalences.
     *
     * The equivalences are a parameter rather than a constant here, because they are the ONE part of
     * this question that is genuinely per engine and cannot be shared: PostgreSQL's `text` and
     * `varchar` are the same storage (`pg_type` reports identical `typlen`, `typalign` and
     * `typstorage`), and MySQL has no such pair at all.
     *
     * @param  list<list<string>>  $equivalences  groups whose members are interchangeable
     */
    public static function sameType(string $left, string $right, array $equivalences): bool
    {
        $left = self::normalize($left);
        $right = self::normalize($right);

        if ($left === $right) {
            return true;
        }

        foreach ($equivalences as $group) {
            $normalized = array_map(self::normalize(...), $group);

            if (in_array($left, $normalized, true) && in_array($right, $normalized, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The declared width of an integer type in bytes, or null when it is not an integer.
     *
     * Named from the type rather than measured from the server, because it is a property of SQL
     * rather than of an instance: `smallint` is two bytes everywhere this package supports. The
     * spellings are both engines' — `int4`/`int8` are PostgreSQL's internal names and appear when a
     * domain is unwrapped.
     */
    public static function integerWidth(string $type): ?int
    {
        return match (self::normalize($type)) {
            'tinyint' => 1,
            'smallint', 'int2', 'smallserial', 'serial2' => 2,
            'mediumint' => 3,
            'integer', 'int', 'int4', 'serial', 'serial4' => 4,
            'bigint', 'int8', 'bigserial', 'serial8' => 8,
            default => null,
        };
    }

    /** Lower-cased and stripped of a declared length or precision, which is not part of the type. */
    private static function normalize(string $type): string
    {
        $bare = strtolower(trim($type));
        $paren = strpos($bare, '(');

        return trim($paren === false ? $bare : substr($bare, 0, $paren));
    }

    /** `orders_customer_fk#0` is one constraint at one position; the name is the part before the `#`. */
    private static function constraintOf(string $edge): string
    {
        $hash = strrpos($edge, '#');

        return $hash === false ? $edge : substr($edge, 0, $hash);
    }

    /** `orders.customer_id=bigint` names `orders.customer_id`. */
    private static function nameOf(string $side): string
    {
        $equals = strpos($side, '=');

        return $equals === false ? $side : substr($side, 0, $equals);
    }

    /** …and its type, or null when the projection carried the name alone because nobody read one. */
    private static function valueOf(string $side): ?string
    {
        $equals = strpos($side, '=');

        if ($equals === false) {
            return null;
        }

        $value = substr($side, $equals + 1);

        return $value === '' ? null : $value;
    }
}
