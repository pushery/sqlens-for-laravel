<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * Where a catalog subject was introduced: the migration file and the line that created it.
 *
 * ## Why an audit finding needs one at all
 *
 * A lint finding knows its file and line, because it reads migrations. A catalog finding reads a
 * DATABASE, and the database has never heard of `2024_01_11_000000_create_orders_table.php` — it
 * knows `public.orders.customer_id`. So an audit finding on a pull request lands in a log, while
 * the person reading that pull request is looking at the migration diff. A finding in a log is one
 * somebody has to go looking for; a finding on the line in the diff is one they read.
 *
 * ## It is PRESENTATION, and that is a hard boundary
 *
 * The anchor never changes a severity, a downtime class, or whether a finding stops a build. It
 * also never enters a finding's fingerprint — a renamed or deleted migration file must not
 * invalidate a baseline entry, because the database it describes did not change when somebody
 * moved a file.
 *
 * ## An absent anchor is a normal answer, not a degraded one
 *
 * Three ordinary cases produce none, and all three are correct rather than gaps:
 *
 *   - the table name is a variable or a constant, so the scan will not guess at it;
 *   - the file does not parse, so the scan has nothing to read;
 *   - there are no migrations at all, which is every application that has run
 *     `schema:dump --prune` — and those are disproportionately the long-lived ones with the most
 *     findings.
 *
 * A finding with no anchor is reported exactly as before. That is why this is a value and not a
 * required field.
 */
final readonly class MigrationAnchor
{
    private function __construct(
        /** Repo-relative where it can be made so, absolute otherwise — whatever the scan was handed. */
        public string $file,
        /** 1-indexed, and the line of the CALL that introduced the subject rather than the file's first. */
        public int $line,
    ) {}

    public static function at(string $file, int $line): self
    {
        return new self($file, $line);
    }

    /** `database/migrations/2024_01_11_000000_create_orders_table.php:14` — for a message a person reads. */
    public function describe(): string
    {
        return $this->file.':'.$this->line;
    }
}
