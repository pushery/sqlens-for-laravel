<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\Shadow\ShadowSweepReport;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What a shadow run's orphan sweep did on the server, as the run reports it.
 *
 * The sweep drops databases, on a server the operator owns, in a run that was asked to look at
 * migrations. That is the one thing such a run must never do quietly, so a sweep with anything to
 * say becomes a notice: a pass naming what it removed, or an undetermined naming what it found and
 * could not remove, or saying that it could not look. A sweep that found nothing says nothing,
 * because there is nothing on the server to account for.
 *
 * Never a failure. What a sweep leaves behind is somebody else's leftovers, not a verdict about the
 * migrations this run judged.
 */
final class ShadowSweepNotice
{
    public static function for(?ShadowSweepReport $report, string $connectionName, SubjectContext $context, string $projectRoot): ?Finding
    {
        if (! $report instanceof ShadowSweepReport || ! $report->hasAnythingToReport()) {
            return null;
        }

        $notice = RunnerNotice::ShadowOrphans;
        $location = Location::inCallsite('shadow:'.$connectionName, 0, 'connection '.$connectionName, $projectRoot);
        $kept = $report->kept();

        if ($report->listed && $kept === []) {
            return Finding::pass(
                $notice->value,
                RunnerNotice::MESSAGE_PREFIX,
                sprintf(
                    'This run removed throwaway databases an earlier, killed shadow run left on this server: %s. '
                    .'SQLens created them for itself, named with its own prefix and the time they were made.',
                    self::names($report->dropped),
                ),
                $location,
                $notice->category(),
                $notice->level(),
                $notice->stability(),
                $notice->documentationUrl(),
                $context,
            );
        }

        $message = $report->listed
            ? sprintf(
                'This run found throwaway databases an earlier, killed shadow run left on this server. %s'
                .'It could not remove %s, most often because a connection is still open on it. The next '
                .'shadow run tries again, or drop it by hand.',
                $report->dropped === [] ? '' : sprintf('It removed %s. ', self::names($report->dropped)),
                self::names($kept),
            )
            : 'The orphan sweep could not list the shadow databases on this server, so a throwaway '
                .'database an earlier, killed run left behind may still be there. The next shadow run '
                .'tries again.';

        return Finding::undetermined(
            $notice->value,
            RunnerNotice::MESSAGE_PREFIX,
            $message,
            UndeterminedReason::ShadowOrphansRemain,
            $location,
            $notice->category(),
            $notice->level(),
            $notice->stability(),
            $notice->documentationUrl(),
            $context,
        );
    }

    /** @param  list<string>  $names */
    private static function names(array $names): string
    {
        return implode(', ', array_map(static fn (string $name): string => '`'.$name.'`', $names));
    }
}
