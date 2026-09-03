<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * One page of a long answer, and the one shape every tool uses to say it is a page.
 *
 * ## Why the ceiling cannot be argued past
 *
 * `agent.mcp.max_findings` is a HARD limit; a caller's `limit` is a wish. A `limit` above the
 * ceiling is capped to it — an agent that could raise the bound by asking would make the setting a
 * suggestion, and the setting exists to keep one tool call from filling a whole context window.
 *
 * ## Why a capped answer says so
 *
 * In the same structured field, every time. A quiet truncation reads exactly like a database with
 * fewer problems than it has — and an agent acting on the short list would report the work as
 * finished. So the answer carries the total, what it returned, whether more remains, and WHY it
 * stopped where it did.
 *
 * One class rather than a convention per tool, because "how a page says it is a page" is precisely
 * the sentence two implementations would come to disagree about.
 */
final readonly class ReportPage
{
    /** Why a page stopped where it did. */
    public const string BY_REQUEST = 'the caller asked for this many';

    public const string BY_CEILING = 'capped at the project ceiling (agent.mcp.max_findings)';

    public const string COMPLETE = 'nothing was left out';

    /**
     * @param  list<array<mixed>>  $rows
     */
    private function __construct(
        public array $rows,
        public int $total,
        public int $offset,
        public bool $truncated,
        public string $reason,
    ) {}

    /**
     * The page a caller gets.
     *
     * @param  list<array<mixed>>  $all
     * @param  int|null  $requested  the caller's `limit`, or null for "as much as allowed"
     */
    public static function of(array $all, int $offset, ?int $requested, int $ceiling): self
    {
        $limit = min($requested ?? $ceiling, $ceiling);
        $rows = array_slice($all, $offset, $limit);
        $truncated = $offset + count($rows) < count($all);

        return new self(
            $rows,
            count($all),
            $offset,
            $truncated,
            match (true) {
                ! $truncated => self::COMPLETE,
                // The ceiling is named whenever it is what actually bound the page — including when
                // a caller asked for more and was capped. Reporting the caller's own number there
                // would hide the setting behind the request that ran into it.
                $requested === null || $requested >= $ceiling => self::BY_CEILING,
                default => self::BY_REQUEST,
            },
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'total' => $this->total,
            'returned' => count($this->rows),
            'offset' => $this->offset,
            'truncated' => $this->truncated,
            'truncation_reason' => $this->reason,
            'findings' => $this->rows,
        ];
    }
}
