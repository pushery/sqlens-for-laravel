<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Pushery\SQLens\Deploy\Events\DeployCheckFinished;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Result;
use Throwable;

/**
 * The end of a deploy command's run, announced as {@see DeployCheckFinished} once the report is
 * written. One trait for both deploy commands, so a listener is told the same thing by each.
 *
 * The exit code is the verdict of the run, and a listener has no say in it: one that throws is
 * reported, and the command returns the code it decided before it announced it.
 */
trait AnnouncesTheDeployCheck
{
    /**
     * Announces how the run ended and returns its exit code.
     *
     * @param  'predeploy'|'postdeploy'  $command
     */
    private function finished(string $command, string $connection, ExitCode $exitCode, bool $waived, Result $result): int
    {
        $event = new DeployCheckFinished($command, $connection, $exitCode->value, $waived, array_map(
            static fn (Finding $finding): array => [
                'rule_id' => $finding->ruleId,
                'status' => $finding->status->outcome->value,
                'message' => $finding->message,
            ],
            $result->findings,
        ));

        try {
            $this->laravel->make(Dispatcher::class)->dispatch($event);
        } catch (Throwable $exception) {
            $this->laravel->make(ExceptionHandler::class)->report($exception);
        }

        return $exitCode->value;
    }
}
