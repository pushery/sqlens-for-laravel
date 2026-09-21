<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * The fixed vocabulary of facts a matrix entry's classification can hinge on — the edges
 * the migration SQL does not show. Each one is a table- or session-level fact (is the table
 * ROW_FORMAT=COMPRESSED? has it a FULLTEXT index? did an ENUM append keep its storage size?)
 * that decides whether an operation runs the cheap way the entry states or falls back to
 * something worse.
 *
 * A matrix condition names one of these by its backed value; a condition naming anything else
 * is a data error, never a silently non-gating note. Prose caveats belong in an entry's
 * `notes`, not here — everything in this enum is a predicate the resolver evaluates.
 */
enum OnlineDdlPredicate: string
{
    /** The table still has room for another row version — after enough INSTANT changes it does not. */
    case InstantRowVersionLimitReached = 'instant_row_version_limit_reached';

    /** The table uses ROW_FORMAT=COMPRESSED, which excludes several otherwise-cheap operations. */
    case RowFormatCompressed = 'row_format_compressed';

    /** The table carries a FULLTEXT index, which forces a rebuild where a plain table would not. */
    case TableHasFulltextIndex = 'table_has_fulltext_index';

    /** The session set foreign_key_checks=0, which changes how adding a foreign key behaves. */
    case ForeignKeyChecksDisabled = 'foreign_key_checks_disabled';

    /** An ENUM/SET change did not grow the column's storage size — the line between metadata-only and rewrite. */
    case EnumStorageSizeUnchanged = 'enum_storage_size_unchanged';

    /**
     * A VARCHAR resize stayed inside one length-byte class. InnoDB spends one length byte below
     * 256 bytes and two at 256 and above, so a resize that crosses that line changes the row
     * format itself and copies the table, while one that stays inside it is metadata-only. The
     * boundary is in BYTES, so the column's character set decides where it falls — which is why
     * a migration's declared character count cannot answer this.
     */
    case VarcharLengthBytesUnchanged = 'varchar_length_bytes_unchanged';

    /**
     * An ENUM/SET redefinition only APPENDED members, at the end of the existing list. Adding one
     * in the middle renumbers every member after it and rewrites the column's stored values. The
     * existing list is not in the statement — only the new one is — so a static reader cannot see
     * where a member landed, which is what makes this a predicate rather than a parse.
     */
    case EnumValueAppendedAtEnd = 'enum_value_appended_at_end';

    /** The table is partitioned, which takes several operations off their in-place path. */
    case TableIsPartitioned = 'table_is_partitioned';

    /**
     * The FULLTEXT index being added is the table's FIRST. Deliberately its own predicate rather
     * than a reuse of {@see self::TableHasFulltextIndex}: that one asks whether an existing
     * FULLTEXT index blocks some OTHER operation's cheap path, and its safe answer is "no such
     * index". Here the polarity is reversed — an existing one is what makes the operation cheap —
     * and folding the two together would give one predicate two safe values.
     */
    case FirstFulltextIndexOnTable = 'first_fulltext_index_on_table';

    /** Another table's foreign key references this column, which narrows the permitted algorithms. */
    case ColumnReferencedByForeignKey = 'column_referenced_by_foreign_key';

    /** A functional index covers the column, which excludes the instant path for dropping it. */
    case ColumnHasFunctionalIndex = 'column_has_functional_index';

    /**
     * An ORDINARY index covers the column — not only a functional one.
     *
     * ⚠️ KEPT APART FROM {@see self::ColumnHasFunctionalIndex} BECAUSE THE MATRIX NAMED ONLY THAT
     * ONE AND THE SERVER REFUSES BOTH. Measured on 8.4.10, with the algorithm pinned:
     *
     *     drop column <stored generated>    no index -> accepted INSTANT, no rebuild
     *     drop column <stored generated>    indexed  -> REFUSED, error 1845
     *     modify … character set utf8mb4    no index -> accepted INPLACE, no rebuild
     *     modify … character set utf8mb4    indexed  -> REFUSED, error 1846
     *
     * Control, so the two refusals are not confused with the one the matrix already knows:
     * `latin1 -> utf8mb4` WITHOUT an index is refused too (1846), and that is
     * {@see self::CharacterSetEncodingUnchanged}. The rows above are a pair that changes no stored
     * byte and still fails — the index is the whole difference.
     *
     * Folding it into the functional-index predicate would give one name two meanings and make the
     * undetermined reason say "functional" about a plain index, which sends a reader to look for
     * something that is not there.
     */
    case ColumnHasIndex = 'column_has_index';

    /**
     * A character-set change leaves the STORED ENCODING alone, so no byte has to be rewritten.
     *
     * Measured on a real MySQL 8.4.10 rather than reasoned about, because the obvious rule is
     * wrong. `utf8mb3` to `utf8mb4` is accepted in place, with `LOCK=NONE`; `latin1` to `utf8mb4`
     * is refused in place entirely and falls back to a copy. So far so expected — but `ascii` to
     * `utf8mb4` is ALSO refused, even though every ASCII byte is already valid UTF-8. This is
     * therefore not "the target encoding is a superset of the source": it is the one pair MySQL
     * treats as a widening of the same encoding, plus conversions that change nothing.
     *
     * A migration names the TARGET character set and not the source, so a lint run usually cannot
     * decide this and reports undetermined; the audit suite reads the catalog and can. That
     * asymmetry is the whole reason this is a predicate rather than a parse.
     */
    case CharacterSetEncodingUnchanged = 'character_set_encoding_unchanged';

    /**
     * The value under which the entry's stated best-case algorithm HOLDS. Most predicates
     * name a hazard that must be ABSENT (false) for the cheap path; the two "unchanged" ones
     * are the opposite — there the cheap path needs the fact to be TRUE.
     *
     * A decided value equal to this is safe; a decided value different from it means the
     * entry's classification does not apply; an undecided value is undetermined — never a
     * silent assumption in either direction.
     */
    public function safeValue(): bool
    {
        return match ($this) {
            self::EnumStorageSizeUnchanged,
            self::VarcharLengthBytesUnchanged,
            self::EnumValueAppendedAtEnd,
            self::CharacterSetEncodingUnchanged => true,
            self::InstantRowVersionLimitReached,
            self::RowFormatCompressed,
            self::TableHasFulltextIndex,
            self::ForeignKeyChecksDisabled,
            self::TableIsPartitioned,
            self::ColumnReferencedByForeignKey,
            self::ColumnHasFunctionalIndex,
            self::ColumnHasIndex,
            self::FirstFulltextIndexOnTable => false,
        };
    }
}
