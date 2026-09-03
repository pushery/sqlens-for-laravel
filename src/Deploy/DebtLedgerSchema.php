<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * Which ledger format this build can act on.
 *
 * ## Why a version at all, and why refusing beats reading anyway
 *
 * The debt account is the one file where being read wrong is worse than not being read. A ledger
 * written by a newer build may carry entries in a shape this one does not understand, and a
 * tolerant reader would drop them — reporting a project as owing nothing at the moment it owes the
 * most. The same is true downward: a version this build has never seen is not an older dialect it
 * can guess at, it is a statement it cannot evaluate.
 *
 * So an unsupported version is a named `undetermined`, never an empty ledger. That is the whole
 * point of the three-valued contract applied to a file: "no debts" and "could not tell" are
 * different answers, and only one of them is safe to act on.
 *
 * ## The window is now two versions wide, and the older one is READ rather than refused
 *
 * Version 2 added `origin` and narrowed the derived identity to kind + object. A version-1 file is
 * still fully readable, and that is a property of how it is read rather than a concession: the
 * loader has always DERIVED each entry's id from its own fields instead of trusting the one in the
 * file, so a version-1 entry arrives with a version-2 identity without anything having to rewrite
 * it. `origin` recovers the same way — an empty migration reference has meant "found in the catalog
 * rather than in a file" since that field existed.
 *
 * So nothing a project committed is lost, and the fields that cannot be recomputed — `first_seen`,
 * `state`, `reason`, `review_at` — are carried through untouched. The file becomes version 2 the
 * next time a recording run writes it.
 *
 * ## The refusal that stays, and why it is the important direction
 *
 * A version this build has never seen is still refused. That is the protective direction: an OLDER
 * build reading a version-2 file would compute identities the old way, produce two entries for one
 * constraint, and report a plausible number — which is precisely the failure the version exists to
 * make impossible. Refusing costs a named `undetermined`; guessing costs a wrong ledger.
 */
final readonly class DebtLedgerSchema
{
    /** The ledger format this build WRITES. */
    public const int CURRENT = 2;

    /**
     * The older formats this build reads, in full, without losing a field.
     *
     * A list rather than "anything below CURRENT": every version here is one somebody checked can
     * be read losslessly by the current loader, and a future version 3 that genuinely cannot read
     * version 1 has to say so by removing it rather than by inheriting a range nobody re-examined.
     */
    public const array READABLE = [1];

    /** Whether this build can act on a ledger written in that format. */
    public static function supports(int $schema): bool
    {
        return $schema === self::CURRENT || in_array($schema, self::READABLE, true);
    }

    /** Whether reading it means upgrading it — true for every format below the current one. */
    public static function isUpgrade(int $schema): bool
    {
        return $schema !== self::CURRENT && in_array($schema, self::READABLE, true);
    }
}
