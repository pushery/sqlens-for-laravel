<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

/**
 * The kinds of element a statement signature is built from. This is the small
 * pattern vocabulary the generic matcher understands; a driver composes its
 * recognition patterns out of these, so no `match` cascade over raw SQL lives in
 * the core.
 */
enum SignatureElementKind
{
    /** A keyword token that must appear here, exactly. */
    case Keyword;

    /** Zero or more skippable modifier keywords (UNIQUE, CONCURRENTLY, IF EXISTS, ONLY, …). */
    case OptionalModifiers;

    /** An identifier token, captured as a target of the element's object type. */
    case Target;

    /** Advance past the next occurrence of a keyword (e.g. ON, REFERENCES); fail the signature if it is absent. */
    case SeekKeyword;

    /**
     * A parenthesized identifier list, captured IN ORDER — `(a, b)` for a key or a reference.
     *
     * Order is the whole point. Index coverage is a LEFT PREFIX: an index on `(a, b)` answers a
     * lookup on `(a)` and one on `(a, b)`, and answers nothing for `(b)`. A set would be useless
     * for that question and actively misleading to the next reader, who would assume it had been
     * considered.
     *
     * It lives here, in the signature vocabulary, rather than in a rule reading the canonical
     * string — putting grammar back into a layer that is deliberately free of it is exactly what
     * this element exists to avoid.
     *
     * **A PLAIN list, or none at all.** The element matches `(a)` and `(a, b)` and declines
     * everything else — `(a varchar_pattern_ops)`, `(lower(a))`, `(a DESC)`, `(a) INCLUDE (b)`.
     * A list with anything besides a comma between its members is not a column list this layer can
     * hand to a coverage question: an operator class swept in as a second column makes a
     * non-comparable index answer for a key it does not serve. Declining leaves the statement to
     * the column-less signature behind it, so it still classifies and simply carries no columns —
     * which every reader turns into "I cannot conclude", never into a wrong conclusion.
     */
    case ColumnList;

    /**
     * Every column a `SET` clause writes FROM ANOTHER COLUMN, in order — the targets of a data MOVE.
     *
     * ## Why the targets and not every name in the clause
     *
     * `SET total_cents = total * 100` names two columns and means different things by them: one is
     * being written, the other is being read. A debt rule asking "was this new column back-filled"
     * needs the first and would be wrong with the second.
     *
     * ## And why only the ones whose VALUE reads a column
     *
     * `SET status = 'new'` and `SET total_cents = total * 100` are the same shape and different
     * events: the first gives a new column a value, the second moves data out of an existing one.
     * Only the second is half of an expand/contract, and only the second is what a debt rule may act
     * on — measured on a committed fixture, where capturing both made that rule fire on the most
     * ordinary migration there is.
     *
     * The test is per ASSIGNMENT, not per clause: `SET a = 1, b = other` yields `[b]` alone. A
     * clause-wide test would let one genuine move vouch for every literal beside it.
     *
     * ## The discriminator is the separator BEFORE the name, and that was measured
     *
     * The obvious rule — an assigned name is one whose FOLLOWING token is preceded by `=` — holds
     * only when the value is itself an identifier. Measured against the real tokenizer, literals
     * produce no token at all, so in `SET a = 1, b = 2` the token after `a` is `b`, preceded by a
     * comma. That rule would have reported both columns as unassigned, which is an incomplete
     * answer wearing the shape of a complete one.
     *
     * What does hold is the shape this element actually uses, and it is the same one
     * {@see self::ColumnList} relies on: the FIRST assigned name follows the `SET` keyword across
     * whitespace, and every later one follows a comma. A name preceded by `=` is a value, a name
     * preceded by `(` is inside an expression, and neither is collected.
     *
     * ## It DECLINES rather than answer partially
     *
     * The run ends at the first token that is not an assignment target, and the signature only
     * matches when that token is one of the clause terminators the driver named (or the end of the
     * statement). PostgreSQL names `FROM`, `WHERE` and `RETURNING`; MySQL names `WHERE`, `ORDER`
     * and `LIMIT`. So `UPDATE orders SET total_cents = total LIMIT 1` read as PostgreSQL stops at a
     * keyword that engine's UPDATE has no clause for, the element declines, and the statement falls
     * through to a signature that captures no columns — a reader then concludes nothing rather than
     * concluding `[total_cents]` about a clause it did not reach the end of.
     *
     * ⚠️ This paragraph used to name `SET a = (SELECT …), b = 2` as the declining case, and that is
     * wrong twice over. MEASURED: it does not decline — it answers `[a]`, because the depth check
     * carries the run past the subquery's `SELECT` to the end of the statement. And `[a]` is the
     * RIGHT answer: `b = 2` assigns a literal, so the sourced test excludes it whatever the run
     * does. The old example described the element before that test existed.
     *
     * That is the same trade `ColumnList` documents: half a list is the one answer that must not
     * travel, because it looks exactly like a whole one.
     */
    case BackfillTargets;

    /**
     * The statement ENDS here — no token may follow.
     *
     * A signature otherwise matches a PREFIX of the tokens, which is right for almost every shape:
     * `ALTER TABLE t ADD CONSTRAINT k …` is that statement whatever trails it. It is wrong for the
     * one shape whose meaning is changed by what trails it — `CREATE INDEX i ON t (a) WHERE …` is
     * a PARTIAL index, and a partial index covers no foreign-key lookup, yet its column list reads
     * exactly like a plain one. Ending the signature is how a driver says "this signature is the
     * whole statement", so the qualified form falls through to the column-less signature instead
     * of being read as the plain one it is not.
     */
    case EndOfStatement;
}
