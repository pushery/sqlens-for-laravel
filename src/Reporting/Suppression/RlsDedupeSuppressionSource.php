<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use JsonException;
use Pushery\SQLens\Findings\Finding;

/**
 * The de-duplication layer for row-level security: when an external catalog reports a fact one of
 * SQLens's own rules already reports, the foreign finding is HIDDEN rather than shown twice — and
 * hidden VISIBLY, with the rule that superseded it named.
 *
 * ## Why the contract exists before any adapter does
 *
 * No PGLS or Splinter adapter is wired yet. That is exactly why this is written down now: the first
 * adapter to land would otherwise decide precedence by accident, and whichever side happened to run
 * first would win. `resources/data/rule-dedupe-rls.json` states it instead — ours wins, because ours
 * carries a severity on our own axis, a downtime class where one applies, and a documentation URL
 * that survives a release.
 *
 * ## Why the foreign finding is suppressed rather than dropped
 *
 * A de-duplicated finding that vanished without trace is indistinguishable from one nobody
 * produced. Reported as suppressed, it stays countable, and the report can say "we already answer
 * this" instead of quietly answering less than the tools installed could. That is the same
 * distinction every other layer here is built on.
 *
 * ## What it will not do
 *
 * It only ever hides a FOREIGN id, never one of our own. Two of our rules covering neighboring
 * ground is a question for those rules, and a suppression layer that could hide one of them would
 * be able to silence a finding nobody chose to silence.
 */
final readonly class RlsDedupeSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'rls_dedupe';

    /** @var array<string, string> foreign rule id => the SQLens rule id that supersedes it */
    private array $superseded;

    /** @param  string|null  $tablePath  the mapping table; null loads the bundled one */
    public function __construct(?string $tablePath = null)
    {
        $this->superseded = $this->read($tablePath ?? dirname(__DIR__, 3).'/resources/data/rule-dedupe-rls.json');
    }

    /**
     * The suppression covering this finding, or null.
     *
     * Null means either the id is not one the contract maps (this source stays out of it) or it is
     * one of ours (never this source's to hide).
     */
    public function supersessionFor(Finding $finding): ?Suppression
    {
        $ours = $this->superseded[$finding->ruleId] ?? null;

        if ($ours === null) {
            return null;
        }

        return new Suppression(
            source: self::SOURCE,
            reason: sprintf(
                'the same fact is reported by %s, which carries this package\'s own severity, downtime class and '
                .'documentation URL; the external check is hidden rather than dropped so the report still shows '
                .'that it ran and what answered it instead',
                $ours,
            ),
        );
    }

    /**
     * The foreign-id index, built once.
     *
     * A malformed or missing table yields an EMPTY index rather than an exception. That direction is
     * deliberate and it is the safe one: an empty index suppresses nothing, so the worst case is a
     * duplicate finding a reader can see. The opposite default — treating an unreadable table as
     * "hide everything" — would silence findings because a file failed to parse.
     *
     * @return array<string, string>
     */
    private function read(string $path): array
    {
        if (! is_file($path)) {
            return [];
        }

        try {
            /** @var array{entries?: array<string, array{foreign?: list<array{id?: string}>}>} $table */
            $table = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [];
        }

        $index = [];

        foreach ($table['entries'] ?? [] as $ours => $entry) {
            foreach ($entry['foreign'] ?? [] as $foreign) {
                if (isset($foreign['id']) && $foreign['id'] !== '') {
                    $index[$foreign['id']] = $ours;
                }
            }
        }

        return $index;
    }
}
