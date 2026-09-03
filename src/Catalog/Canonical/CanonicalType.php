<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Canonical;

/**
 * A column's type, in one spelling — with the server's own spelling kept beside it.
 *
 * Both are needed and neither is enough. A rule that asks "is this an integer?" cannot be written
 * against two catalogs that answer `integer` and `int`; a rule that asks "is this `tinyint(1)`?"
 * cannot be written against a canonical name that has thrown the width away. So the canonical name
 * is what rules compare on, and `raw` is what they fall back to when the question is genuinely
 * engine-specific — which for the level-6 idiom rules it often is.
 *
 * ## Two mappings this deliberately does NOT make
 *
 * Both are tempting, both would be wrong, and both were found by reading what the servers actually
 * return rather than by reasoning about type names:
 *
 * - **`tinyint(1)` is not `boolean`.** It is the convention Laravel uses for one, and MySQL 8.4
 *   keeps the width on `tinyint` for exactly that reason while having dropped display widths from
 *   every other integer. But the column can hold -128 to 127, and canonicalizing it to `boolean`
 *   would erase that — quietly, in the layer whose job is to stop information from being erased.
 * - **MySQL's `timestamp` is not PostgreSQL's `timestamp`.** MySQL's is time-zone aware (stored as
 *   UTC and converted on the way out); PostgreSQL's is time-zone NAIVE, and its aware type is
 *   `timestamptz`. Mapping the two names together would equate a correct column with the exact
 *   mistake the level-6 rule about `timestamptz` exists to report.
 *
 * Where two engines genuinely mean the same thing, they get the same canonical name. Where they do
 * not, they keep different ones, and a rule that cares says which engine it is talking about.
 */
final readonly class CanonicalType
{
    /**
     * The cross-engine spellings that DO mean the same thing.
     *
     * Read off both catalogs rather than recalled: PostgreSQL's `information_schema` answers in
     * SQL-standard spellings (`integer`, `character varying`) while its own catalog answers in
     * internal ones (`int4`, `varchar`), and MySQL answers in a third set (`int`, `varchar`). All
     * three reach this map.
     *
     * @var array<string, string>
     */
    private const array ALIASES = [
        // Integers. MySQL 8.4 no longer reports a display width on these, which is why none is
        // stripped here — measured, not assumed away.
        'int' => 'integer',
        'int4' => 'integer',
        'int8' => 'bigint',
        'int2' => 'smallint',
        'mediumint' => 'integer',
        'serial' => 'integer',
        'bigserial' => 'bigint',
        'smallserial' => 'smallint',

        // Exact decimals. PostgreSQL calls it `numeric`, MySQL calls it `decimal`, the standard
        // permits both, and they are the same type.
        'decimal' => 'numeric',
        'dec' => 'numeric',

        // Text.
        'character varying' => 'varchar',
        'character' => 'char',
        'bpchar' => 'char',
        'longtext' => 'text',
        'mediumtext' => 'text',
        'tinytext' => 'text',

        // Floating point.
        'float4' => 'real',
        'float8' => 'double precision',
        'double' => 'double precision',

        // Time. `timestamptz` and its long spelling are the SAME type; MySQL's `timestamp` is
        // deliberately NOT mapped to either (see the class docblock).
        'timestamptz' => 'timestamp with time zone',
        'timetz' => 'time with time zone',

        // Boolean. `bool` is PostgreSQL's own short name for its own boolean — not MySQL's
        // `tinyint(1)`, which is a different type wearing the same intent.
        'bool' => 'boolean',
    ];

    private function __construct(
        /** The spelling rules compare on. */
        public string $name,
        /** What the server called it, verbatim, modifiers and all. */
        public string $raw,
        public ?int $length,
        public ?int $precision,
        public ?int $scale,
        /** MySQL's `unsigned`; always false on PostgreSQL, which has no such modifier. */
        public bool $unsigned,
    ) {}

    /**
     * Read a catalog's answer as a canonical type.
     *
     * `$raw` is the server's fullest spelling — PostgreSQL's `format_type()` output or MySQL's
     * `COLUMN_TYPE` — because that is where the modifiers live. The bare name is derived from it
     * rather than taken from a second column, so the two can never disagree.
     */
    public static function fromRaw(string $raw, ?int $length = null, ?int $precision = null, ?int $scale = null): self
    {
        $normalized = mb_strtolower(trim($raw));
        $unsigned = str_contains($normalized, ' unsigned');

        // Strip the modifiers the name does not include: `unsigned`, `zerofill`, an array suffix,
        // and the parenthesised precision. What is left is the type's own name.
        $bare = preg_replace('/\s+(unsigned|zerofill)\b/', '', $normalized) ?? $normalized;
        $bare = preg_replace('/\s*\([^)]*\)/', '', $bare) ?? $bare;
        $bare = trim(preg_replace('/\[\]$/', '', $bare) ?? $bare);

        return new self(
            self::ALIASES[$bare] ?? $bare,
            trim($raw),
            $length,
            $precision,
            $scale,
            $unsigned,
        );
    }

    /** Whether this is the given canonical type, whatever the server spelled it. */
    public function is(string $canonicalName): bool
    {
        return $this->name === mb_strtolower($canonicalName);
    }

    /**
     * @return array{name: string, raw: string, length: int|null, precision: int|null, scale: int|null, unsigned: bool}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'raw' => $this->raw,
            'length' => $this->length,
            'precision' => $this->precision,
            'scale' => $this->scale,
            'unsigned' => $this->unsigned,
        ];
    }
}
