<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * The maintenance-window advice a finding carries, derived from its downtime class alone.
 *
 * ## What it deliberately does NOT say
 *
 * No duration. Not in seconds, not as a range, not as "roughly". A number here would look like
 * knowledge and be a guess: how long a rewrite takes depends on the row count, the hardware and
 * the concurrent load, none of which a static reader has seen. A guessed duration is worse than
 * no duration, because a reader plans against it — and the plan fails at exactly the moment the
 * window matters. Concrete time and size statements belong to the deploy suite, which reads real
 * statistics.
 *
 * What it does say is the SHAPE of the precaution: what kind of window this needs, and what to do
 * instead. That is derivable from the class with certainty, which is why it can be a template.
 *
 * ## Why it is derived rather than written per rule
 *
 * A rule that phrased its own advice would drift from every other rule's, and twenty rules would
 * eventually give twenty answers to one question. The class already carries the fact; the advice
 * is a restatement of it for a human, so it belongs where the class is interpreted — once.
 */
enum MaintenanceWindow: string
{
    /**
     * The operation holds a lock other sessions wait behind. The precaution is timing plus a
     * bounded wait, so a queue that forms cannot grow without limit.
     */
    case OffPeakWithLockTimeout = 'off_peak_with_lock_timeout';

    /**
     * The operation rewrites the table. Its cost grows with the table, so the precaution is either
     * a real window or not doing it in place at all.
     */
    case ScheduledOrExpandContract = 'scheduled_or_expand_contract';

    /**
     * The advice for a downtime class, or null when the class needs none.
     *
     * `online` gets nothing, and that is the point of the field being optional: an operation that
     * blocks nobody needs no window, and attaching a sentence to it would train readers to skip
     * the sentence on the operations that do.
     */
    public static function forDowntimeClass(?DowntimeClass $downtimeClass): ?self
    {
        return match ($downtimeClass) {
            DowntimeClass::Blocking => self::OffPeakWithLockTimeout,
            DowntimeClass::Rewrite => self::ScheduledOrExpandContract,
            DowntimeClass::Online, null => null,
        };
    }

    /** The sentence a reader sees. Fixed text: the same finding reads the same on every machine. */
    public function advice(): string
    {
        return match ($this) {
            self::OffPeakWithLockTimeout => 'Other sessions queue behind this operation while it runs. Run it outside peak load, and set lock_timeout so a queue that forms cannot grow without limit.',
            self::ScheduledOrExpandContract => 'This rewrites the table, so its cost grows with the table. Schedule a maintenance window for it, or avoid the rewrite entirely with an expand/contract migration.',
        };
    }
}
