<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Capture\CapturedStatement;

/**
 * The migrations this deploy is about to run, as the preflight sees them.
 *
 * A thin type over the resolver's answer, and it exists for one reason: the checks must not depend
 * on the resolver's shape. A check asks "which objects are about to be touched", and the day that
 * answer is assembled differently, one type changes rather than every check.
 *
 * Empty is a legitimate and common state — a deploy with no pending migrations is a deploy, and a
 * gate that treated it as a problem would fire on every second release.
 */
final readonly class PendingWork
{
    /**
     * @param  list<string>  $files  the migration files, in the order the deploy will apply them
     * @param  list<CapturedStatement>  $statements  the captured statements themselves, from the
     *                                               same run `lint` judged — they carry `canonicalSql`,
     *                                               `statementKind` and `targets`, so a caller never
     *                                               has to parse the SQL a second time
     */
    public function __construct(
        public array $files = [],
        public array $statements = [],
    ) {}

    public function isEmpty(): bool
    {
        return $this->files === [];
    }
}
