<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use DateTimeImmutable;
use DateTimeZone;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * How long a debt has been outstanding, in UTC calendar days.
 *
 * ## The reference is a parameter, never the wall clock
 *
 * This package already settled that question for statistics freshness, and the reason is the same
 * here: a value that read the clock itself would answer differently every time it was asked, and
 * two runs over an unchanged ledger would disagree about a database that had not moved. The caller
 * names the instant it is measuring against — which is also what makes a frozen clock a test
 * detail rather than a framework dependency.
 *
 * (The ticket suggested a `Clock` binding or Carbon's test helpers. Neither is used, because the
 * package's existing answer is stronger: there is nothing to forget to inject.)
 *
 * ## Calendar days, not 86400-second blocks
 *
 * A debt recorded on the 1st and read on the 2nd is one day old, whatever hour either happened at.
 * Counting elapsed seconds instead would make the same pair of dates answer 0 or 1 depending on the
 * time of day, and a threshold at exactly 90 days would flip back and forth across an afternoon.
 * Both ends are reduced to their UTC calendar date first, so the ambient timezone of the process —
 * and any daylight-saving transition inside the interval — cannot move the answer.
 *
 * ## A debt from the future is reported, never rounded away
 *
 * A `first_seen` after the reference means one of two things, and both are real: a machine wrote
 * the ledger with a skewed clock, or somebody edited the file. Clamping to zero would turn either
 * into "recorded today", which is the reassuring reading and the wrong one — a debt would look
 * brand new every time it was read.
 */
final readonly class DebtAge
{
    private function __construct(
        private ?int $days,
        public ?UndeterminedReason $reason = null,
        public ?string $detail = null,
    ) {}

    /**
     * The age of a debt first seen on that date, measured against that instant.
     *
     * @param  string  $firstSeen  a `YYYY-MM-DD` calendar date, as the ledger records it
     */
    public static function between(string $firstSeen, DateTimeImmutable $reference): self
    {
        $utc = new DateTimeZone('UTC');

        try {
            // `setTimezone()` before `setTime()`, and the order is the whole point: the constructor's
            // timezone argument is a FALLBACK that PHP drops the moment the string carries an offset
            // of its own, so without this the midnight below would be midnight THERE rather than on
            // the UTC calendar day. The reference gets the same treatment on the other end.
            $from = new DateTimeImmutable($firstSeen, $utc)->setTimezone($utc)->setTime(0, 0);
        } catch (Throwable $error) {
            return new self(null, UndeterminedReason::DebtAgeUnknown, sprintf(
                'the debt records `first_seen` as "%s", which is not a date this build can read '
                .'(%s), so how long it has been outstanding is unknown. It is NOT treated as new: '
                .'an unreadable date on an old debt would report it as recorded today.',
                $firstSeen,
                $error->getMessage(),
            ));
        }

        $to = $reference->setTimezone($utc)->setTime(0, 0);

        // Reduced to whole days by the diff of two midnight-UTC instants, so the hour either end
        // happened at cannot move the answer.
        $days = (int) $from->diff($to)->days * ($to < $from ? -1 : 1);

        if ($days < 0) {
            return new self(null, UndeterminedReason::DebtAgeUnknown, sprintf(
                'the debt records `first_seen` as %s, which is AFTER the %s this run measures '
                .'against. Either the machine that recorded it had a skewed clock or the ledger was '
                .'edited by hand; both are real, and clamping the age to zero would report an old '
                .'debt as brand new on every run.',
                $from->format('Y-m-d'),
                $to->format('Y-m-d'),
            ));
        }

        return new self($days);
    }

    public function isKnown(): bool
    {
        return $this->days !== null;
    }

    /**
     * The age in whole UTC calendar days.
     *
     * Null rather than a stand-in when it could not be established. A caller that wants a number
     * has to say what it does with the absence — which is the three-valued contract arriving at a
     * value object.
     */
    public function days(): ?int
    {
        return $this->days;
    }
}
