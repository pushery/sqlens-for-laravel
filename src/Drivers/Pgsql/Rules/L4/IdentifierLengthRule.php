<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExplicitIdentifierTemplate;
use Pushery\SQLens\Rules\Convention\IdentifierLength;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * An identifier PostgreSQL will silently rename.
 *
 * PostgreSQL's limit is `NAMEDATALEN - 1` = **63 BYTES**, and going over it is not an error.
 * Measured against 18.4:
 *
 * ```
 * NOTICE:  identifier "aaaa…" (64 chars) will be truncated to "aaa…" (63)
 * NOTICE:  identifier "<32 two-byte chars>" (64 bytes) will be truncated to 31 characters
 * CREATE TABLE
 * ```
 *
 * The statement SUCCEEDS. The object exists under a name nobody wrote, the `NOTICE` goes to a
 * channel no migration runner surfaces, and every later reference by the written name fails — long
 * after the deploy that caused it, with nothing connecting the two.
 *
 * The second line is why the measurement is in BYTES. Thirty-two two-byte characters are thirty-two
 * characters and sixty-four bytes: a rule counting characters passes exactly the identifier the
 * server is about to rename. The sister rule on MySQL counts characters, measured, and the two
 * cannot share a measurement even though they share a subject.
 *
 * ## Lint only, and that is structural rather than a gap
 *
 * An over-long identifier NEVER REACHES THE CATALOG. PostgreSQL truncated it on the way in — so by the time an audit
 * reads the schema there is nothing over the limit to find. An audit half here would be a check that
 * cannot fail, which this package treats as worse than an absent one: it reports a clean result over
 * a question it never asked.
 *
 * The migration is the only place the written name still exists.
 */
final class IdentifierLengthRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    private readonly ExplicitIdentifierTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null, ?ExplicitIdentifierTemplate $template = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = $template ?? new ExplicitIdentifierTemplate;
    }

    /**
     * The fix is an argument — but it is only a fix for a statement that has the problem.
     *
     * The shape is read through {@see self::overLongNames()}, the SAME call the judgment makes
     * rather than a second copy of the condition. A copy is the failure this seam is guarded
     * against: it agrees on the day it is written and drifts silently afterwards, and what a
     * reader gets is a work order for a problem that is not there.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->overLongNames($statement) === []) {
            return null;
        }

        return $this->template->forPostgres([], $this->id(), $this->downtimeClass());
    }

    public function id(): string
    {
        return 'PG.L4.IDENTIFIER_LENGTH';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** No lock and no rewrite — the statement either succeeds under another name or is refused. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $names = $this->overLongNames($statement);

        if ($names === []) {
            return null;
        }

        // One sentence per offending name, in ONE verdict: the contract deduplicates a second
        // verdict for the same statement by rule id and location, so a statement introducing three
        // long names would report one and drop two WITHOUT SAYING SO.
        $described = [];

        foreach ($names as $name) {
            $described[] = $this->describe($name);
        }

        return implode(' ', $described);
    }

    /**
     * Every name this statement writes that the server will not accept as written.
     *
     * Static and shared, so the judgment and the fix material can never disagree about whether
     * there is a problem. It reads the statement's targets AND the columns a key names: reading
     * only the table would miss the case that actually bites, because Laravel derives an index or
     * constraint name from the table AND its columns, and the derived name goes over while every
     * name a person typed is comfortably under.
     *
     * @return list<string> sorted, deduplicated, and empty when the statement is fine
     */
    private function overLongNames(MigrationStatementView $statement): array
    {
        $over = [];

        foreach ($statement->targets as $target) {
            $bare = IdentifierLength::bareName($target->qualifiedName());

            if ($bare !== '' && IdentifierLength::exceeds($bare, IdentifierLength::POSTGRES_BYTES, true)) {
                $over[$bare] = true;
            }
        }

        foreach ($statement->keyColumns as $column) {
            $bare = IdentifierLength::bareName($column);

            if ($bare !== '' && IdentifierLength::exceeds($bare, IdentifierLength::POSTGRES_BYTES, true)) {
                $over[$bare] = true;
            }
        }

        $names = array_keys($over);
        sort($names, SORT_STRING);

        return $names;
    }

    /** One sentence about one offending name. */
    private function describe(string $name): string
    {
        return 'The identifier `'.$name.'` is over PostgreSQL\'s 63-byte limit, so the server creates it as '
            .'`'.IdentifierLength::truncated($name, IdentifierLength::POSTGRES_BYTES).'` and says so only in a NOTICE. '
            .'Every later reference by the name written here will fail.';
    }
}
