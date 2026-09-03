<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What `sqlens:postdeploy` learned by replaying the migrations — including "it did not ask".
 *
 * ## Three states, and the third is the one that had to be built
 *
 * `compared` and `unavailable` are the two a comparison can reach on its own. The third is
 * `notRequested`, and it exists because the option is OFF by default: without it the report would
 * be indistinguishable from a comparison that ran and found nothing, and a reader would take "no
 * drift findings" for "the schema matches its migrations". It does not mean that. It means nobody
 * looked.
 *
 * That distinction is the same three-valued discipline the rest of the package runs on, applied one
 * level up — to a whole comparison rather than to a single check. Every state therefore carries a
 * {@see $note} that is printed on EVERY run, whichever way it went.
 *
 * ## The findings are the drift command's findings, not a second set
 *
 * They come from {@see DriftFindings::of()}, the same call `sqlens:drift` makes, so a comparison run
 * from either command produces byte-identical documents for the part they share. Two code paths
 * answering "does this database match its migrations" would be free to disagree, and would the first
 * time somebody fixed a normalization in one of them.
 */
final readonly class ExpectationReport
{
    private function __construct(
        /** Whether `--expect-shadow` was passed at all. */
        public bool $requested,
        /** Whether a comparison actually happened — false when it was not asked for OR could not run. */
        public bool $compared,
        /** @var list<Finding> */
        public array $findings,
        /**
         * The qualified names the comparison found live in the database and absent from the
         * migration state.
         *
         * Held separately from the findings rather than re-derived from them, because
         * {@see ExpectationEscalation} needs the SET and reading it back out of finding messages is
         * the parsing this package refuses everywhere else: it works until the wording changes.
         *
         * @var list<string>
         */
        public array $unexpectedObjects,
        /** Printed on every run — the sentence that keeps "I did not look" from reading as "it matches". */
        public string $note,
    ) {}

    /** The option was not passed: nothing was replayed, and the report says so out loud. */
    public static function notRequested(): self
    {
        return new self(false, false, [], [],
            'sqlens:postdeploy: the schema was NOT compared against the migrations — pass '
            .'--expect-shadow to replay them into a shadow database and prove the match. Without it '
            .'this run read the catalog only, so a hotfix applied straight to this database is '
            .'invisible to it.',
        );
    }

    /** The option was passed and the comparison could not be built — a named reason, never a pass. */
    public static function unavailable(string $reason): self
    {
        return new self(true, false, [], [],
            'sqlens:postdeploy: --expect-shadow was requested and no expectation could be built, so '
            .'the schema is UNCOMPARED rather than matching: '.$reason,
        );
    }

    public static function compared(DriftReport $report, SubjectContext $context, string $connection): self
    {
        $unexpected = array_map(
            static fn (DriftEntry $entry): string => $entry->qualifiedName,
            $report->of(DriftClass::UnexpectedInDatabase),
        );

        return new self(
            true,
            true,
            DriftFindings::of($report, $context, $connection),
            $unexpected,
            sprintf(
                'sqlens:postdeploy: the schema was compared against the migrations by shadow replay '
                .'— %d difference(s), %d of them objects no migration describes, %d blind spot(s).',
                count($report->entries),
                count($unexpected),
                count($report->blindSpots),
            ),
        );
    }

    /**
     * The block this run contributes to the report's own context — including "it did not run".
     *
     * A shape rather than a flag, because the three states carry different information and a
     * consumer that had to infer "not requested" from an absence would infer it from the same
     * absence a comparison producing nothing leaves.
     *
     * @return array{requested: bool, compared: bool, note: string}
     */
    public function block(): array
    {
        return ['requested' => $this->requested, 'compared' => $this->compared, 'note' => $this->note];
    }

    /**
     * Whether the comparison itself produced a failing finding.
     *
     * Asked of the FINDINGS rather than of the entry count, because the two can differ: an entry
     * this run excluded produces no finding, and an exit code derived from the count would then
     * fail a run whose document holds nothing to act on.
     */
    public function blocks(): bool
    {
        return array_any($this->findings, fn (Finding $finding): bool => $finding->status->outcome === Outcome::Fail);
    }
}
