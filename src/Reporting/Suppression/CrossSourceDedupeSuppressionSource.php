<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One risk reported twice — once as the migration that causes it, once as the state it produced.
 *
 * `sqlens:security` runs both halves and concatenates their findings, so a `GRANT … TO PUBLIC` in a
 * migration and the grant sitting in the catalog arrive as two entries about one fact. The reader
 * fixes it once and sees it reported twice, which is how a report starts being skimmed.
 *
 * ## Identity is the whole difficulty, and the rule id is NOT it
 *
 * Merging on the rule id alone is the wrong merge: two different tables, one rule, collapsed into an
 * entry that is true of neither. So this matches on the rule id AND the schema object, and a finding
 * that names no object is never matched — "no target" is not an agreement, it is an absence, and
 * treating the two alike is exactly the substitution this package refuses everywhere else.
 *
 * ## ⚠️ NO SHIPPED RULE REACHES THIS LAYER, AND FOR GRANTS THAT IS A DECISION, NOT A GAP
 *
 * The two halves of a grant finding share none of the three fields this matches on. The migration
 * side's id carries an `_IN_MIGRATION` suffix (`SEC.PRIV.GRANT_PUBLIC_IN_MIGRATION` against
 * `SEC.PRIV.GRANT_PUBLIC`), it names the statement's table where the catalog names a `Grant`, and so
 * the names differ too. Measured over the whole `SEC.PRIV.*` family, 7 rules against 15. Pairing them
 * looked like the missing half of this layer, and it is not wanted:
 *
 * The migration half of `sqlens:security` judges the PENDING set. A pending `GRANT … TO PUBLIC` is
 * not the live grant reported a second time; it is the next deploy granting it again. The two
 * findings carry two remedies, revoke the live grant and change the migration, and suppressing the
 * second as "the same fact" would hide that the first does not survive the next deploy.
 *
 * The privilege question that pairing raised is answered for the day a migration half reads
 * migrations that have already run: a grant finding's identity carries its privilege set, and the
 * migration side is the same fact only when its set is CONTAINED in the catalog's. Equality is too
 * strict, because the catalog may hold more from another route, and any overlap is too loose, because
 * a live `SELECT` does not report a migration's `INSERT`. `ALL` compares through the catalog's own
 * `all_privileges`, because the set it expands to depends on the object and the server version.
 *
 * What the layer covers is the case where both halves name the same rule and the same object, the
 * shape it was written for and the shape the arms pin. No rule in the security category produces it
 * today: the rules that report from both halves under one id are schema rules outside it.
 *
 * A migration statement legitimately has no single target: several relations, a `DO $$` block. Those
 * findings stay standing, on purpose, and stay standing beside each other — two of them agreeing on
 * having no target agree on nothing.
 *
 * ## Why the CATALOG side wins
 *
 * The direction is fixed rather than decided per pair. A catalog finding is the state as it IS; a
 * migration finding is one route by which it got there, and there may be routes the run cannot see.
 * Hiding the state to keep the cause would leave a report that describes history rather than the
 * database — and a project that dropped the migration from its tree would then report nothing at all
 * about a grant that is still live.
 *
 * ## And why this suppresses rather than merges
 *
 * The ticket asked for a merged finding carrying `sources: [lint, audit]`. That is a second model for
 * a problem this package already answers: a duplicate is suppressed and SHOWN as suppressed, with
 * the rule that owns it named — the promise the published optional-analyzers page makes for foreign
 * tools, made here for our own two halves. It keeps both records intact instead of synthesizing a
 * hybrid that neither half reported, and it needs no new field in the report envelope.
 */
final readonly class CrossSourceDedupeSuppressionSource
{
    // ⚠️ SNAKE_CASE, AND IT WAS THE ONLY HYPHENATED ONE OF EIGHT. Its seven siblings spell themselves
    // `audit_ignore`, `destructive_opt_in`, `rls_dedupe`, `paired_view_dedupe` — and this string is a KEY
    // in the JSON envelope's `suppressed_by_source` object, so one hyphen among eight underscores is a
    // shape a consumer has to special-case forever.
    //
    // Renamed now because it is FREE now: this layer has never fired in any run, so no consumer has ever
    // seen the old spelling in output. The same rename after it starts working is a breaking change to a
    // published envelope.
    public const string SOURCE = 'cross_source_dedupe';

    /**
     * The identity of every catalog finding in this run — the set a migration finding may match.
     *
     * Built once by the resolver from the complete candidate list, for the same reason the paired
     * views' id list is: entitlement to hide something depends on what ELSE reported, so it cannot
     * be answered one finding at a time.
     *
     * @param  list<Finding>  $candidates
     * @return list<string>
     */
    public static function catalogIdentities(array $candidates): array
    {
        $keys = [];

        foreach ($candidates as $finding) {
            if ($finding->location->kind !== LocationKind::Catalog) {
                continue;
            }

            $key = self::identity($finding);

            if ($key !== null) {
                $keys[$key] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * @param  list<string>  $catalogIdentities
     */
    public function supersessionFor(Finding $finding, array $catalogIdentities): ?Suppression
    {
        // Only the migration side is ever hidden. Asserted here rather than assumed from the caller,
        // because a catalog finding whose identity is in its own set would otherwise suppress itself
        // — the set is built from exactly these findings.
        if ($finding->location->kind !== LocationKind::Migration) {
            return null;
        }

        $key = self::identity($finding);

        if ($key === null || ! in_array($key, $catalogIdentities, true)) {
            return null;
        }

        return new Suppression(
            source: self::SOURCE,
            reason: sprintf(
                'the same fact is reported against %s from the catalog, which is the state as it '
                .'stands rather than one route to it; this migration finding was CHECKED and matched, '
                .'not skipped, and it names the same rule (%s) about the same object',
                (string) $finding->location->objectName,
                $finding->ruleId,
            ),
        );
    }

    /**
     * The identity two findings must share, or null when this finding does not have one.
     *
     * Null rather than a fabricated key: a finding with no object cannot be shown to be about the
     * same thing as anything, and a placeholder would make every such finding identical to every
     * other one.
     */
    private static function identity(Finding $finding): ?string
    {
        $name = $finding->location->objectName;
        $type = $finding->location->objectType;

        if ($name === null || $name === '' || ! $type instanceof SchemaObjectType) {
            return null;
        }

        return implode("\x1f", [$finding->ruleId, $type->value, $name]);
    }
}
