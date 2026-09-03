<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Pushery\SQLens\Exceptions\UnreasonedUndetermined;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What the run could NOT answer — the section this whole format exists to make unmissable.
 *
 * An agent reading a report with no failure list concludes the run was clean and says so. That is
 * the single most expensive mistake available here, and the agent loop is where it costs most:
 * nobody looks again afterwards. A skip that is merely omitted is indistinguishable, from inside
 * the document, from a check that ran and passed.
 *
 * So the section is ALWAYS present, says "0" out loud when it is empty, and gives every entry a
 * named reason plus the next thing to do about it.
 *
 * ## The action is per FAMILY, not per reason
 *
 * The reasons already carry their own explanation, and many of them already say what to do — "check
 * the configured matrix path", "repair it from version control". Repeating that per reason would be
 * a second copy of a sentence that already exists, and the two would drift.
 *
 * What a description cannot say is the thing that is true of a whole CLASS of skip: that a check
 * defeated by static reading needs the shadow mode, that a missing tool is an install or a
 * deliberate opt-out, that a missing privilege is a grant somebody has to decide on. Those four
 * sentences are added here, beside the reason rather than instead of it.
 */
final readonly class UndeterminedSection
{
    /**
     * The families that get an action, and the action.
     *
     * Keyed by reason so the mapping is data rather than a chain of conditionals; a reason not in
     * here renders its description alone, which is the honest outcome when the description already
     * carries the action.
     *
     * @var array<string, string>
     */
    private const array ACTIONS = [
        // Defeated by reading alone. The shadow mode is the answer, and it is the answer a reader
        // is least likely to already know.
        UndeterminedReason::PretendLimit->value => 'Run in shadow mode so the migration is executed against a throwaway database and the statement can be read.',
        // The pre-scan's own verdict: this migration decides what to do from a query result, or
        // reaches past the schema builder, so its statements do not exist until it runs.
        UndeterminedReason::PreScanFlagged->value => 'Run in shadow mode: the pre-scan found this migration decides what it does at run time, so its statements do not exist to be read.',
        // A tool the strict mode required and did not find.
        UndeterminedReason::MissingExternalTool->value => 'Install the tool at the version this build was measured against, or drop strict tool mode for this run and accept the reduced coverage knowingly.',
        // A privilege somebody has to decide to grant.
        UndeterminedReason::MissingPrivilege->value => 'Grant the reading role this privilege, or accept that this check cannot run here and record why.',
        // Nothing answered at all.
        UndeterminedReason::ServerUnreachable->value => 'Make the instance reachable from where this ran, then check again — nothing about it was established.',
        UndeterminedReason::UnknownServerVersion->value => 'Pin the version with sqlens.assume_server_version, or run where the server can be asked.',
    ];

    /**
     * The section, always — including when there is nothing in it.
     *
     * @param  list<Finding>  $findings  every finding of the run, in the order they should appear
     * @return list<string>
     *
     * @throws UnreasonedUndetermined
     */
    public function render(array $findings): array
    {
        $unresolved = array_values(array_filter(
            $findings,
            static fn (Finding $finding): bool => $finding->status->outcome === Outcome::Undetermined,
        ));

        $lines = ['## What could not be checked', ''];

        if ($unresolved === []) {
            // The explicit zero. Absence is never expressed by omission: a missing section and a
            // clean run look identical to whoever is reading, and only one of them is safe to act
            // on.
            return [...$lines, '**0 undetermined.** Every check this run selected was able to answer.', ''];
        }

        $lines[] = '**'.count($unresolved).' undetermined.** These are NOT passes. A check that could not run has';
        $lines[] = 'established nothing, and treating one as clean is the most expensive mistake available here.';
        $lines[] = '';

        foreach ($unresolved as $finding) {
            $lines = [...$lines, ...$this->entry($finding)];
        }

        return $lines;
    }

    /**
     * One entry: what could not be checked, why, and what to do.
     *
     * @return list<string>
     *
     * @throws UnreasonedUndetermined
     */
    private function entry(Finding $finding): array
    {
        $reason = $finding->status->reason;

        if (! $reason instanceof UndeterminedReason) {
            // The producing code's bug, reported as one. Rendering it silently would put an
            // unexplained skip in front of a reader who has no way to act on it — which is the
            // shape of the failure this whole section exists to prevent, arriving from inside.
            throw new UnreasonedUndetermined;
        }

        $lines = [
            '### '.$finding->ruleId,
            '',
            '- '.$finding->message,
            '- **Why it could not answer:** '.$reason->description(),
        ];

        $action = self::ACTIONS[$reason->value] ?? null;

        if ($action !== null) {
            $lines[] = '- **Next:** '.$action;
        }

        return [...$lines, ''];
    }
}
