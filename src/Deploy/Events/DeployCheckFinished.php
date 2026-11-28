<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Events;

/**
 * How a run of `sqlens:predeploy` or `sqlens:postdeploy` ended, dispatched once its report is
 * written, for a listener that records which rules fell, such as one that hands them on to an error
 * tracker for each database a deploy checks.
 *
 * It carries values and no object of the run, so a queued listener takes it as it is. A run the
 * command refuses before it reads the database, the misconfiguration exit, dispatches nothing,
 * because it has no report and no finding to carry.
 */
final readonly class DeployCheckFinished
{
    /**
     * @param  'predeploy'|'postdeploy'  $command  the command that ran, without its `sqlens:` prefix
     * @param  string  $connection  the connection the run read
     * @param  int  $exitCode  the exit code the command returns
     * @param  bool  $waived  whether a waiver let the run through what could not answer, as `undetermined_waiver` in the run header of the report says
     * @param  list<array{rule_id: string, status: string, message: string}>  $findings  every finding of the report in its order, each with the rule id, the status and the message the JSON report gives it
     */
    public function __construct(
        public string $command,
        public string $connection,
        public int $exitCode,
        public bool $waived,
        public array $findings,
    ) {}
}
