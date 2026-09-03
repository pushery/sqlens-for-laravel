<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * How a debt came to be known — and therefore what its `first_seen` date actually means.
 *
 * ## Why the ledger has to say this out loud
 *
 * Every entry carries one date, and until the catalog could register a debt that date had one
 * meaning: the day a run first saw the migration that took the debt on. Close enough to "when we
 * did this" to be read that way, and it was read that way.
 *
 * A debt observed in the database with no captured migration behind it cannot mean that. Nobody
 * knows when a legacy `NOT VALID` constraint was created; the statement ran in some earlier deploy,
 * possibly years ago, possibly before this package existed. Its `first_seen` is the day somebody
 * first LOOKED. That is honest and it is useful — an age measured from the day you started counting
 * is still an age — but it is a different sentence from the one beside it in the same file.
 *
 * Two dates that mean different things and look identical is the shape this package refuses
 * everywhere else: a skip with no reason, a pass that could not run, a count with no ground set. So
 * the entry says which it is, and a reader never has to guess.
 *
 * ## Why not solve it in the documentation instead
 *
 * That was the alternative, and it loses for a mechanical reason rather than a stylistic one: the
 * ledger is read by `get_debt_ledger`, by the reporters and by the escalation path, none of which
 * read documentation. A field they can branch on is available to all of them; a paragraph is
 * available to none.
 */
enum DebtOrigin: string
{
    /**
     * A captured migration in this repository took the debt on.
     *
     * `first_seen` is the day a run first saw that migration, which is as close to "when we did
     * this" as a repository can honestly get.
     */
    case Migration = 'migration';

    /**
     * Observed in the database, with no captured migration behind it.
     *
     * `first_seen` is the day a run first looked — NOT the day the debt was taken on, which nothing
     * available to this package knows. The oldest debt a project carries is usually one of these,
     * and before it could be recorded it was the only kind with no date at all.
     */
    case Catalog = 'catalog';

    /**
     * The origin a ledger written before this field existed implies.
     *
     * Derived rather than defaulted: a schema-1 entry names its migration when it had one, and an
     * empty migration reference was already documented as "found in the catalog rather than in a
     * file". So the old format carried the answer all along, in a field nobody had asked that
     * question of, and reading it back is a recovery rather than a guess.
     */
    public static function impliedBy(string $migration): self
    {
        return trim($migration) === '' ? self::Catalog : self::Migration;
    }
}
