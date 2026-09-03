<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/**
 * The three ways two readings of one schema can disagree.
 *
 * Three and not two: "different" is not one fact. An object that exists only in the database, one
 * that exists only in the migration state, and one that exists in both under different definitions
 * have different CAUSES and different remedies, and a comparator that reported them as one kind
 * would hand its reader a list they have to re-sort by hand before they can act on any of it.
 */
enum DriftClass: string
{
    /**
     * Live in the database, absent from the migration state — the hotfix-straight-into-production
     * case, and the reason this whole comparison exists.
     *
     * It is the most valuable of the three because it is the only one no other tool notices: the
     * migrations all ran, the deploy was green, and the schema still holds something no file
     * describes. The next `migrate:fresh` on a rebuilt environment silently loses it.
     */
    case UnexpectedInDatabase = 'unexpected_in_database';

    /**
     * In the migration state, absent from the database — a migration that failed, was skipped, or
     * was rolled back and never re-applied.
     *
     * Usually louder than the case above (the application reaches for it and fails), but not
     * always: a column nothing reads yet can be missing for months.
     */
    case MissingInDatabase = 'missing_in_database';

    /** Present on both sides under one name, described differently. */
    case Divergent = 'divergent';

    /**
     * The catalog id a finding of this class reports under — ONE id per class, not one id carrying
     * the class as a field.
     *
     * ## The decision, and what it costs either way
     *
     * A baseline entry is fingerprinted over the rule id together with the location. With one id
     * per class, an object that moves from `missing_in_database` to `divergent` — the migration
     * finally ran, and now the two definitions disagree — produces a DIFFERENT fingerprint, so a
     * baseline that accepted the first does not silently accept the second. That is the behavior
     * worth having: the two are different facts with different remedies, and the second one arriving
     * unannounced under an accepted entry is precisely the silent green this package refuses.
     *
     * The single-id shape would have been cheaper here and wrong there: one accepted entry would
     * cover every way that object can ever disagree, for as long as the baseline lives.
     *
     * The price is real and is paid knowingly: three ids mean three pages, three catalog rows, and
     * a project that wants to mute drift entirely mutes three things rather than one. A suite filter
     * (`deploy`) and the shared `DEPLOY.DRIFT.` prefix both already exist for exactly that, so the
     * cost lands on configuration rather than on correctness.
     */
    public function ruleId(): string
    {
        return match ($this) {
            self::UnexpectedInDatabase => 'DEPLOY.DRIFT.UNEXPECTED_IN_DATABASE',
            self::MissingInDatabase => 'DEPLOY.DRIFT.MISSING_IN_DATABASE',
            self::Divergent => 'DEPLOY.DRIFT.DIVERGENT',
        };
    }

    /** What a reader should understand the class to mean, in one line. */
    public function description(): string
    {
        return match ($this) {
            self::UnexpectedInDatabase => 'exists in the database and in no migration',
            self::MissingInDatabase => 'the migrations describe it and the database does not have it',
            self::Divergent => 'both sides have it and describe it differently',
        };
    }
}
