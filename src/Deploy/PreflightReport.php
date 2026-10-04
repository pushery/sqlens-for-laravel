<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\CredentialRedaction;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What a whole preflight run answered.
 *
 * The two lists are kept apart deliberately. `$results` is what the run LEARNED; `$notApplicable`
 * is what it never asked because the question does not exist on this engine. Merging them would
 * require a fourth outcome value, and the report is a public contract from 1.0 on.
 */
final readonly class PreflightReport
{
    /**
     * @param  list<CheckResult>  $results
     * @param  list<string>  $notApplicable  check ids the running driver excluded
     * @param  array<string, int>  $timings  milliseconds per check that ran, in check order
     */
    public function __construct(
        public array $results = [],
        public array $notApplicable = [],
        public array $timings = [],
    ) {}

    /**
     * The same report with every reason redacted — the one place a run's words leave the checks.
     *
     * See {@see CheckResult::redactedWith()} for the measurement behind it. Applied to the REPORT
     * rather than inside each check because a check is where the sentence is worth writing and a
     * report is where it is worth sanitizing: the eleven that quote a database error each have a
     * good reason to, and the twelfth would otherwise arrive without the treatment.
     */
    public function redactedWith(CredentialRedaction $redaction): self
    {
        return new self(
            array_map(static fn (CheckResult $result): CheckResult => $result->redactedWith($redaction), $this->results),
            $this->notApplicable,
            $this->timings,
        );
    }

    /**
     * The per-check timings as one line, slowest first — for the message a broken budget prints.
     *
     * Sorted rather than left in check order on purpose: a budget failure is read by somebody
     * looking for the cause, and the cause is at the top. Check order is what the report itself
     * carries, and this is not the report.
     */
    public function describeTimings(): string
    {
        $timings = $this->timings;
        arsort($timings);

        return implode(', ', array_map(
            static fn (string $id, int $ms): string => $id.'='.$ms.'ms',
            array_keys($timings),
            array_values($timings),
        ));
    }

    /**
     * Whether a fail-closed gate should stop the deploy.
     *
     * `undetermined` counts, and that IS the fail-closed contract: a gate that could not look has
     * not established that the deploy is safe, and treating "I do not know" as "go ahead" is the
     * assumption this package exists to refuse. `--allow-undetermined` is the deliberate way out,
     * and it lives on the command rather than here — the report states what it found, the caller
     * decides what to do about it.
     */
    public function blocks(): bool
    {
        return array_any($this->results, static fn (CheckResult $r): bool => $r->isBlocking());
    }

    /** @return list<CheckResult> the ones that could not answer, with their reasons */
    public function undetermined(): array
    {
        return array_values(array_filter(
            $this->results,
            static fn (CheckResult $r): bool => $r->outcome === Outcome::Undetermined,
        ));
    }

    /** @return list<Finding> everything every check found, in check order */
    public function findings(): array
    {
        return array_merge(...array_map(static fn (CheckResult $r): array => $r->findings, $this->results));
    }

    /**
     * One undetermined finding for each check that could not answer and has no finding saying so.
     *
     * An undetermined result carries its reason as a sentence on the result, not as a finding, so a
     * report built from the findings alone left the check out entirely: `--format=json` listed
     * nothing for it, `summary.counts` counted its reason as 0, and a deploy script reading the
     * document at exit 3 could not tell which check held the deploy or why. The console wrote the
     * sentence to stderr, the one stream an archived report does not keep.
     *
     * The check id is the finding's rule id, the reason its undetermined reason and the sentence its
     * message, so every surface built from the findings carries all three. Kept apart from
     * {@see self::findings()} on purpose: that list is also read for debts, where every object name
     * counts as still owed, and the database a check could not read is not a debt.
     *
     * An undetermined finding never breaches a gate, so the verdict and the exit code do not move.
     *
     * @return list<Finding>
     */
    public function undeterminedGaps(string $driver, string $connection, string $profile): array
    {
        $gaps = [];

        foreach ($this->undetermined() as $result) {
            if (! $result->undeterminedReason instanceof UndeterminedReason || $this->saysItself($result)) {
                continue;
            }

            $gaps[] = Finding::undetermined(
                $result->checkId,
                DeployNotice::MESSAGE_PREFIX,
                (string) $result->reason,
                $result->undeterminedReason,
                Location::inCatalog($driver, $connection, $connection, SchemaObjectType::Database),
                Category::Safety,
                Level::Capturable,
                StabilityTier::Stable,
                RuleDocumentationUrl::for($result->checkId),
                new SubjectContext(driver: $driver, profile: $profile, strictTools: false),
            );
        }

        return $gaps;
    }

    /** Whether an undetermined result already carries an undetermined finding of its own. */
    private function saysItself(CheckResult $result): bool
    {
        return array_any($result->findings, static fn (Finding $finding): bool => $finding->status->outcome === Outcome::Undetermined);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'results' => array_map(static fn (CheckResult $r): array => $r->toArray(), $this->results),
            // Present even when empty, unlike a null field: "no check was inapplicable" is
            // information, and a consumer comparing two runs needs the key to exist in both.
            'not_applicable' => $this->notApplicable,
        ];
    }
}
