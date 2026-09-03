<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Convention;

use Pushery\SQLens\Exceptions\InvalidNamingPattern;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One judgment about an identifier's shape, shared by the PostgreSQL and MySQL rules.
 *
 * ## Why a convention rule earns a place in a database-safety tool
 *
 * Naming taste is not this package's business. Case is, and only on these two engines, because on
 * both of them a mixed-case identifier means something different from what it looks like:
 *
 * - **PostgreSQL folds an unquoted identifier to lower case.** `CREATE TABLE "Orders"` and
 *   `CREATE TABLE Orders` do not make the same table: the first is `Orders`, the second is `orders`,
 *   and afterwards `SELECT * FROM Orders` finds the second and not the first. A schema with both
 *   spellings has two tables that a reader believes are one.
 * - **MySQL's answer depends on `lower_case_table_names`**, which is a SERVER setting and differs
 *   between a developer's Mac (2) and a Linux server (0). The same migration therefore produces one
 *   table on the laptop and a different one in production — and the failure surfaces as "table
 *   doesn't exist" long after the deploy that caused it.
 *
 * So this is not tidiness at level 8: it is the shape that makes the two engines' case rules stop
 * mattering. That is also why the rule is exactly this narrow — it asks whether an identifier can
 * survive both engines unquoted, and nothing else.
 *
 * ## What it deliberately does NOT do
 *
 * No filtering of extension objects, partitions or prefixed tables. That work is the catalog
 * reader's, done once for every rule, and a second copy here would drift from it — the negative
 * fixtures prove the pass-through rather than re-implementing it.
 */
final readonly class SnakeCaseIdentifiers
{
    /**
     * The shape an identifier must have to mean the same thing on both engines, unquoted.
     *
     * Leading digit excluded on purpose: `2fa_secret` is a syntax error unquoted on PostgreSQL, so
     * an identifier that starts with one is the very case this rule exists for rather than a
     * stylistic quibble.
     */
    public const string DEFAULT_PATTERN = '/^[a-z][a-z0-9_]*$/';

    /**
     * The object kinds this rule judges — and the list is SHORTER than it looks like it should be.
     *
     * A column, an index and a constraint are missing on purpose. They are members of a table, and
     * this repository's catalog rules speak ONCE per object, naming every offending member in that
     * one finding — a convention held by an architecture test rather than by prose, because it was
     * got wrong five times before anyone noticed. Judging a column as its own subject would report
     * one finding per bad name and, worse, report the same name twice on a reading that carries the
     * table and its columns both.
     *
     * So the members are read off the table below, and what is left here is the objects that stand
     * on their own: a view, a materialized view and a sequence are reached by name and belong to
     * nobody. Roles, grants, settings and extensions are absent for a different reason — they are
     * not names the project chose.
     *
     * @var non-empty-list<SchemaObjectType>
     */
    public const array JUDGED_TYPES = [
        SchemaObjectType::Table,
        SchemaObjectType::View,
        SchemaObjectType::MaterializedView,
        SchemaObjectType::Sequence,
    ];

    /**
     * The kinds a MIGRATION statement may introduce, which is a wider set.
     *
     * The lint path has no table object to hang a column on — it has a statement and the targets
     * that statement touches — so a column, an index and a constraint are judged there directly.
     * One verdict per statement still holds: the names are gathered and reported together.
     *
     * @var non-empty-list<SchemaObjectType>
     */
    public const array JUDGED_TARGET_TYPES = [
        SchemaObjectType::Table,
        SchemaObjectType::Column,
        SchemaObjectType::Index,
        SchemaObjectType::Constraint,
        SchemaObjectType::View,
        SchemaObjectType::MaterializedView,
        SchemaObjectType::Sequence,
    ];

    /**
     * The attributes a table carries that hold its members' names, keyed by what to call them.
     *
     * Read from the encoded member lists the catalog reader attaches, rather than from a second
     * query: those lists are already filtered for extension objects, partitions and the table
     * prefix, and a rule that went back to the catalog itself would lose all three.
     *
     * @var array<string, string>
     */
    public const array MEMBER_ATTRIBUTES = [
        'columns' => 'column',
        'indexes' => 'index',
        'unique_indexes' => 'index',
        'foreign_keys' => 'constraint',
    ];

    /**
     * Every member name on a table that deviates, keyed by name and valued by what kind it is.
     *
     * Read off the encoded member lists the catalog reader already attached, never by going back to
     * the catalog: those lists are filtered for extension objects, partitions and the Laravel table
     * prefix, and a rule that asked the server itself would lose all three filters and report on
     * objects nobody owns.
     *
     * Keyed by name so a column and an index that happen to share one are reported once — and
     * sorted, because the order a reader sees must not depend on which attribute the catalog
     * happened to fill first.
     *
     * @return array<string, string>
     */
    public static function offendingMembers(SchemaObject $object, string $pattern = self::DEFAULT_PATTERN): array
    {
        $offenders = [];

        foreach (self::MEMBER_ATTRIBUTES as $attribute => $kind) {
            foreach (self::memberNames($object->getString($attribute) ?? '') as $name) {
                if (self::violates($name, $pattern)) {
                    $offenders[$name] = $kind;
                }
            }
        }

        ksort($offenders);

        return $offenders;
    }

    /**
     * The member names out of one encoded list, whichever of the two shapes it is in.
     *
     * The catalog reader encodes a plain list as `a; b` and a list with payload as `a(x, y); b(z)`,
     * and both shapes reach this rule: `columns` is the first, `indexes` and `foreign_keys` are the
     * second. Reading only one of them would leave a whole class of name unjudged and look exactly
     * like a schema that had none.
     *
     * @return list<string>
     */
    private static function memberNames(string $encoded): array
    {
        $names = [];

        foreach (explode(';', $encoded) as $entry) {
            $entry = trim($entry);
            $open = mb_strpos($entry, '(');
            $name = $open === false ? $entry : trim(mb_substr($entry, 0, $open));

            if ($name !== '') {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * Whether this identifier deviates from the shape both engines can carry unquoted.
     *
     * ## Why a pattern PCRE cannot compile is refused rather than read
     *
     * `preg_match()` answers `false` for such a pattern, not `0`, and `false !== 1` — so the obvious
     * comparison turns one typo in a project's pattern into "every identifier is a violation".
     * Measured with `/^[a-z/`: `violates('orders')` came back `true`, and `orders` is the canonical
     * good name in this rule's own default. Nothing in that report points at the configuration.
     *
     * The silence operator is deliberate and is the narrow kind: the only diagnostic `preg_match()`
     * raises here is about the pattern, and it is not swallowed — it is re-read below and becomes
     * the sentence of a named exception, which says more than the warning did.
     *
     * @throws InvalidNamingPattern when the pattern cannot be compiled
     */
    public static function violates(string $identifier, string $pattern = self::DEFAULT_PATTERN): bool
    {
        if ($identifier === '') {
            return false;
        }

        $matched = @preg_match($pattern, $identifier);

        if ($matched === false) {
            throw InvalidNamingPattern::unusable($pattern, self::whyPcreRefused($pattern, $identifier));
        }

        return $matched !== 1;
    }

    /**
     * PCRE's own sentence about the pattern, captured from the diagnostic it raises.
     *
     * Re-running the match is the price of one exception and nothing else: this is reached only on
     * the path that is about to throw. `preg_last_error_msg()` is not used because it answers
     * "Internal error" for a compilation failure — true, and useless to somebody looking for the
     * character they mistyped.
     */
    private static function whyPcreRefused(string $pattern, string $identifier): string
    {
        $diagnostic = null;

        set_error_handler(static function (int $number, string $message) use (&$diagnostic): bool {
            $diagnostic ??= $message;

            return true;
        });

        try {
            preg_match($pattern, $identifier);
        } finally {
            restore_error_handler();
        }

        if (! is_string($diagnostic)) {
            return preg_last_error_msg();
        }

        // `preg_match(): Compilation failed: …` — the prefix names the function a reader never
        // called, so it goes and the part that locates the mistake stays.
        return str_starts_with($diagnostic, 'preg_match(): ')
            ? substr($diagnostic, strlen('preg_match(): '))
            : $diagnostic;
    }

    /**
     * The bare identifier out of a qualified name.
     *
     * A column arrives as `schema.table.column` and a table as `schema.table`, so the last segment
     * is the name this rule is about. Splitting on the LAST dot rather than the first is what keeps
     * a schema called `My_Schema` from being reported once per column it contains — the schema is
     * its own object and gets judged once, on its own.
     */
    public static function bareName(string $qualifiedName): string
    {
        $lastDot = mb_strrpos($qualifiedName, '.');

        return $lastDot === false ? $qualifiedName : mb_substr($qualifiedName, $lastDot + 1);
    }

    /**
     * What is wrong with it, in the words a reader can act on.
     *
     * Naming the specific deviation rather than restating the pattern: "contains an upper-case
     * letter" tells somebody what to change, `/^[a-z][a-z0-9_]*$/` makes them work it out. Ordered
     * so the FIRST reason is the one that bites on both engines.
     */
    public static function reason(string $identifier): string
    {
        return match (true) {
            $identifier !== mb_strtolower($identifier) => 'it carries an upper-case letter, so it '
                .'means one thing quoted and another unquoted',
            preg_match('/^\d/', $identifier) === 1 => 'it starts with a digit, which PostgreSQL '
                .'refuses unquoted',
            str_contains($identifier, '-') => 'it contains a hyphen, which parses as subtraction '
                .'unquoted',
            str_contains($identifier, ' ') => 'it contains a space, so every reference to it has to '
                .'be quoted',
            default => 'it contains a character outside a-z, 0-9 and underscore',
        };
    }
}
