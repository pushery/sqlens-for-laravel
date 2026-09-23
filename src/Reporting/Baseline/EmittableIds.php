<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use JsonException;
use Pushery\SQLens\Catalog\RuleRegistryExport;
use Pushery\SQLens\Resources\ShippedJson;
use Pushery\SQLens\Tools\Squawk\SquawkRuleIds;

/**
 * Every id this package can put into a report — which is exactly the set a baseline may name.
 *
 * ## Why the rule registry is not enough, and finding that out cost a red gate
 *
 * The first version of the baseline check treated "known" as "there is a `Rule` object with this
 * id", the way an ignore list does. That is wrong for a baseline, and wrong in the direction that
 * refuses valid input: a project can accept a `CAP.L0.NOT_CAPTURABLE`, an
 * `AUDIT.CATALOG.UNREAD.INSUFFICIENT_PRIVILEGE` or a `SEC.SKIPPED.PG.AUTHID` just as deliberately
 * as it accepts a rule finding — none of those is a `Rule`, and every one of them is a finding
 * somebody looked at and decided to live with. Measured: four suites went red on ids their own
 * baseline commands had written moments earlier.
 *
 * So the set comes from the shipped registry artifact, whose whole contract is "everything this
 * build can emit" and which has its own completeness guard. The tools' declared ids are added for
 * the reason they are added to an ignore list: a suppression naming a tool rule has to stay valid
 * on a machine where the tool is absent.
 *
 * ## Families are prefixes, not ids
 *
 * A row marked `covers: family` stands for a whole family: `AUDIT.CATALOG.UNREAD` is the row and
 * `AUDIT.CATALOG.UNREAD.INSUFFICIENT_PRIVILEGE` is what gets emitted. A membership test comparing the
 * concrete id against the family row would reject every one of them, so family rows match as
 * prefixes and everything else exactly.
 *
 * The family's own NAME counts as well, because some families emit it: `LINT.SKIPPED` is a family
 * (`LINT.SKIPPED.MISSING_TOOL` is a member) and an id the lint runner produces on its own. Requiring
 * the separator would reject an id this build really does write.
 */
final readonly class EmittableIds
{
    /** @param  list<string>  $exact */
    private function __construct(
        private array $exact,
        /** @var list<string> */
        private array $families,
    ) {}

    /**
     * Read from the shipped artifact, which must be there.
     *
     * An unreadable artifact is an exception, not an empty set. An empty set would make every id
     * unknown and refuse every baseline on earth, and treating empty as "cannot judge" only moves the
     * problem: `BaselineRuleIds` would read the same empty set and return no findings at all, so the
     * baseline-id check switches itself off, while the `RuleIdValidator` path calls every `CAP.*` and
     * `SQUAWK.*` ignore id unknown. One empty set, two opposite conclusions, neither of them "the file
     * is missing".
     *
     * Refusing says the true thing once, in the one place that can know it. The tolerance stays on
     * {@see self::fromFile()}, where a suite legitimately supplies an absent or truncated artifact —
     * the difference being whether the path was a parameter.
     */
    public static function shipped(): self
    {
        // Read ONCE per process, the same way the Squawk map and the online-DDL matrix are. The
        // artifact is 92 KB of JSON and the baseline check runs at the start of every audit, so a
        // suite that drives hundreds of runs would parse it hundreds of times — and a shipped file
        // cannot change under a running process, so a second read could only ever return the same
        // answer more slowly.
        static $bundled = null;

        if (! $bundled instanceof self) {
            $path = dirname(__DIR__, 3).'/'.RuleRegistryExport::BUNDLED_FILE;

            // Strict here, tolerant in `fromFile()` — the difference is whether the path was a
            // parameter. The decode result is discarded on purpose: this call is the REFUSAL, and the
            // parsing below stays where it already was.
            ShippedJson::decode($path);

            $bundled = self::fromFile($path);
        }

        return $bundled;
    }

    /**
     * The same, from a named artifact — the form a test can put into every state the shipped one is
     * never in: absent, truncated, or carrying a row without an id.
     */
    public static function fromFile(string $path): self
    {
        if (! is_file($path)) {
            return new self([], []);
        }

        try {
            /** @var array{entries?: list<array{id?: string, covers?: string}>} $decoded */
            $decoded = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new self([], []);
        }

        $exact = SquawkRuleIds::suppressible();
        $families = [];

        foreach ($decoded['entries'] ?? [] as $entry) {
            $id = $entry['id'] ?? null;
            // A named condition rather than `||`: Rector splits the combined form into two ifs, and
            // the half a well-formed artifact never reaches then sits on a line nothing executes.
            $unusable = ! is_string($id) || $id === '';

            if ($unusable) {
                continue;
            }

            if (($entry['covers'] ?? '') === 'family') {
                $families[] = $id;

                continue;
            }

            $exact[] = $id;
        }

        return new self(array_values(array_unique($exact)), array_values(array_unique($families)));
    }

    /** Whether the set loaded at all. An empty one cannot judge anything and must not try. */
    public function isEmpty(): bool
    {
        return $this->exact === [] && $this->families === [];
    }

    public function knows(string $id): bool
    {
        if (in_array($id, $this->exact, true)) {
            return true;
        }

        // `array_any` rather than a loop with an early return: Rector rewrites the loop into exactly
        // this, and the rewritten form is the one the coverage floor can account for.
        return array_any(
            $this->families,
            // The family's own name counts too — see the class docblock: `LINT.SKIPPED` is a family
            // AND an id the lint runner emits on its own.
            static fn (string $family): bool => $id === $family || str_starts_with($id, $family.'.'),
        );
    }

    /**
     * The exact ids, for a validator that wants to offer a near-miss suggestion.
     *
     * @return list<string>
     */
    public function all(): array
    {
        return $this->exact;
    }
}
