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
 * The only thing two such findings are guaranteed to share is the rule id, and merging on that alone
 * is the wrong merge: two different tables, one rule, collapsed into an entry that is true of
 * neither. So this matches on the rule id AND the schema object, and a finding that names no object
 * is never matched — "no target" is not an agreement, it is an absence, and treating the two alike
 * is exactly the substitution this package refuses everywhere else.
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
    public const string SOURCE = 'cross-source-dedupe';

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
