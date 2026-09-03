<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\CatalogReader;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * What a post-deploy check is allowed to look at, and how long it has.
 *
 * ## Why this is NOT {@see PreflightContext} with a flag
 *
 * The two moments ask about different worlds, and the difference is exactly one field: preflight
 * carries {@see PendingWork} — the statements that are ABOUT to run. After `migrate --force` there
 * is no such thing. Passing an empty `PendingWork` here would let a check quietly answer "nothing
 * pending, therefore nothing to say" at the one moment where the catalog is the only truth left.
 *
 * So the pending set is absent by construction rather than empty by convention. A check written for
 * this moment cannot ask a question it has no business asking.
 *
 * ## What it does share, on purpose
 *
 * The session, the budget, the readers and {@see CheckResult} are the same, because "read a catalog
 * under a bounded, lockless session and answer in three values" is one mechanism. A second
 * implementation of it would be a second opinion, and the day the two disagreed nobody could say
 * which was right.
 */
final readonly class PostdeployContext
{
    public function __construct(
        /** The instance being verified. Named rather than implied: a replica has a different truth. */
        public string $connection,
        public string $driver,
        public ServerVersion $serverVersion,
        public ReaderSession $session,
        public string $profile,
        /**
         * When this run must be finished, as an `hrtime(true)` reading.
         *
         * Postdeploy is not monitoring: it runs ONCE and ends. The budget is what makes that
         * structural rather than a promise — a verifier that could take arbitrarily long is a
         * daemon nobody meant to write.
         */
        private int $deadlineAt,
        public ?CatalogReader $catalog = null,
        public ?ActivityReader $activity = null,
    ) {}

    /** How much of the budget is left, floored at zero. */
    public function remainingBudgetMs(): int
    {
        return max(0, (int) (($this->deadlineAt - hrtime(true)) / 1_000_000));
    }

    public function isExhausted(): bool
    {
        return $this->remainingBudgetMs() <= 0;
    }
}
