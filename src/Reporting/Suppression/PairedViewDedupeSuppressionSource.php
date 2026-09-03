<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use JsonException;
use Pushery\SQLens\Findings\Finding;

/**
 * Two of our own rules read the same server setting from different angles; this shows ONE of them
 * and records the other as suppressed against it.
 *
 * ## The pair, and why it exists at all
 *
 * `general_log = ON` is a hardening finding — `CREATE USER … IDENTIFIED BY` writes the password into
 * that log — and a privacy finding, because every row value in every statement goes in with it. One
 * category per rule is a deliberate constraint of this package, so the two angles are two rules, and
 * a run on a production MySQL server produces both for one server value. Reporting both unchanged
 * counts one problem twice, and a report that double-counts is read as inaccurate.
 *
 * ## Why this is NOT the same shape as {@see RlsDedupeSuppressionSource}
 *
 * That one is a static table: a foreign checker's finding is superseded by ours whether ours fired
 * or not, because ours is the authoritative reading of that fact. Correct there, and wrong here.
 *
 * Both ids in this table are OURS, and the privacy view may only step aside when its hardening
 * partner is genuinely in the report. Otherwise it disappears with nothing in its place — and a
 * report missing a category is indistinguishable from a clean one. That is the failure this whole
 * package is built against, so the table alone can never be the verdict: it states the pair, and the
 * RUN decides.
 *
 * ## What "genuinely in the report" means, and why it is stricter than "was produced"
 *
 * The partner must be VISIBLE, not merely present among the candidates. A project that ignores the
 * hardening rule through config, accepts it in a baseline or annotates it away has a run where the
 * hardening view is produced and then hidden — and if the privacy view deferred to it anyway, BOTH
 * would be gone and the server value nobody looked at would be reported by nothing.
 *
 * That cannot be decided while resolving one candidate, because whether the partner survives is only
 * known once every candidate is resolved. So {@see SuppressionResolver::resolve()} does it in a
 * second pass and hands anything orphaned back to the visible set. The measured consequence is
 * pinned in `tests/Feature/Reporting/PairedViewDedupeTest.php`.
 */
final readonly class PairedViewDedupeSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'paired_view_dedupe';

    /** @var array<string, string> the privacy rule id => the hardening rule id it defers to */
    private array $superseded;

    /** @param  string|null  $tablePath  the mapping table; null loads the bundled one */
    public function __construct(?string $tablePath = null)
    {
        $this->superseded = $this->read($tablePath ?? dirname(__DIR__, 3).'/resources/data/rule-dedupe-views.json');
    }

    /**
     * The hardening view this finding defers to, or null when it is not the deferring half of a pair.
     *
     * Public because the resolver's second pass needs the same answer after the fact — it has to ask
     * "was the partner of this suppressed finding actually shown?" and the id is the only way to ask.
     */
    public function supersedingIdFor(string $ruleId): ?string
    {
        return $this->superseded[$ruleId] ?? null;
    }

    /**
     * The suppression covering this finding, or null.
     *
     * @param  list<string>  $reportedIds  the rule ids that produced a finding in THIS run. A pair
     *                                     whose hardening half is silent leaves the privacy half
     *                                     standing — that is the whole difference from a static table.
     */
    public function supersessionFor(Finding $finding, array $reportedIds): ?Suppression
    {
        $hardening = $this->superseded[$finding->ruleId] ?? null;

        if ($hardening === null || ! in_array($hardening, $reportedIds, true)) {
            return null;
        }

        return new Suppression(
            source: self::SOURCE,
            reason: sprintf(
                'the same server setting is already reported by %s, which reads it as a hardening '
                .'problem and carries the higher severity of the pair; this privacy view was CHECKED '
                .'and is part of that finding rather than a second one, and the fix is the same '
                .'setting either way',
                $hardening,
            ),
        );
    }

    /**
     * The pair index, built once.
     *
     * A malformed or missing table yields an EMPTY index rather than an exception, the same direction
     * its RLS sibling takes and for the same reason: an empty index suppresses nothing, so the worst
     * case is a duplicate finding a reader can see. Treating an unreadable file as "hide everything"
     * would silence findings because a file failed to parse.
     *
     * @return array<string, string>
     */
    private function read(string $path): array
    {
        if (! is_file($path)) {
            return [];
        }

        try {
            /** @var array{entries?: array<string, array{superseded_by?: string}>} $table */
            $table = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [];
        }

        $index = [];

        foreach ($table['entries'] ?? [] as $privacyId => $entry) {
            $hardening = $entry['superseded_by'] ?? '';

            if ($hardening !== '') {
                $index[$privacyId] = $hardening;
            }
        }

        return $index;
    }
}
