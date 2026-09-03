<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

/**
 * How much a statistics number is worth — the difference between a planner's guess and a
 * measurement.
 *
 * Two classes, and the reason there are only two is that the boundary between them is the only one
 * a consumer can act on. A number is either something the server computed while answering, or
 * something it remembered from the last time somebody asked it to look.
 *
 * This is NOT a field anybody sets. {@see Estimate} derives it from the freshness, which follows
 * from which factory built the value, so there is no second place for it to be stated and therefore
 * no way for two statements to disagree. A precision a call site passed would be a precision a call
 * site could pass wrongly — and there is exactly one way to pass it wrongly, the way that launders
 * an estimate into a measurement.
 */
enum EstimatePrecision: string
{
    /**
     * The number came out of stored statistics, and it is a guess.
     *
     * How large a guess depends on the engine and on when the statistics were last refreshed —
     * MySQL documents its InnoDB row counts as varying from the truth by as much as forty to fifty
     * percent — so the size of the error is not knowable from the number. That is precisely why it
     * must never reach a rule: a check comparing it against a threshold would answer differently on
     * the same schema depending on when statistics were last refreshed, and would have no way to
     * say so.
     */
    case Estimated = 'estimated';

    /**
     * The server computed this while answering, so it was true at the moment of the read.
     *
     * PostgreSQL's size functions are the case that exists today: they stat the files, so the byte
     * count is real rather than remembered. "At read time" is doing work in the name — it is exact,
     * and it is already historical by the time anybody reads the report.
     *
     * MySQL has no counterpart. Its data length is pages allocated multiplied by page size, which
     * approximates allocation rather than measuring content, so a table just emptied still reports
     * the pages it holds. A consumer that assumed "a byte count is exact" would therefore be right
     * on one engine and quietly wrong on the other — which is why the same quantity can arrive here
     * in either class, decided by the driver that read it.
     */
    case ExactAtReadTime = 'exact_at_read_time';

    /** Whether a number of this class may be trusted as a measurement rather than a guess. */
    public function isExact(): bool
    {
        return $this === self::ExactAtReadTime;
    }
}
