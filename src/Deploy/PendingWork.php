<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Subjects\MigrationDirection;

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
     * @param  bool  $statementsComplete  whether `$statements` is everything the deploy will run:
     *                                    true only when every pending migration's `up()` was
     *                                    captured. A check that concludes from an ABSENCE among the
     *                                    statements may do so only then; a migration the capture
     *                                    could not determine contributes none
     */
    public function __construct(
        public array $files = [],
        public array $statements = [],
        public bool $statementsComplete = false,
    ) {}

    public function isEmpty(): bool
    {
        return $this->files === [];
    }

    /**
     * Whether a check may conclude from what the statements do not contain: every pending migration
     * was captured, and every `up()` statement handed over was read into canonical form.
     *
     * A capture that passes carries no statement it could not canonicalize, so in a run the second
     * half holds whenever the first does. It is asked anyway, because a check that concluded "nothing
     * here waits" from a statement it never read would be answering for something it did not see.
     * Only `up()` runs at deploy time, so a rollback statement decides nothing here.
     */
    public function readInFull(): bool
    {
        return $this->statementsComplete && array_all(
            $this->statements,
            static fn (CapturedStatement $statement): bool => $statement->direction !== MigrationDirection::Up || $statement->canonicalSql !== null,
        );
    }
}
