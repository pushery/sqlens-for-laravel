<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L4;

use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExplicitIdentifierTemplate;
use Pushery\SQLens\Rules\Convention\IdentifierLength;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * An identifier MySQL will refuse.
 *
 * MySQL's limit is **64 CHARACTERS** for most object names, and going over it is a hard error.
 * Measured against 8.4.10:
 *
 * ```
 * ERROR 1059 (42000): Identifier name 'bbbb…' is too long
 * ```
 *
 * The statement is refused, the deploy stops, and the message names the identifier. That is the good
 * failure mode — loud, immediate, in front of somebody who can act — which is why this rule is worth
 * having anyway: it moves that failure from the deploy to the diff.
 *
 * The unit is CHARACTERS, not bytes. The same thirty-two two-byte characters PostgreSQL truncates
 * are created here without complaint, measured — so the sister rule counts bytes and this one counts
 * characters, and a shared measurement would be wrong on one engine.
 *
 * ## Lint only, and that is structural rather than a gap
 *
 * An over-long identifier NEVER REACHES THE CATALOG. MySQL refused the statement outright — so by the time an audit
 * reads the schema there is nothing over the limit to find. An audit half here would be a check that
 * cannot fail, which this package treats as worse than an absent one: it reports a clean result over
 * a question it never asked.
 *
 * The migration is the only place the written name still exists.
 */
final class IdentifierLengthRule extends AbstractMysqlRule implements ProvidesRemediation
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

        return $this->template->forMysql([], $this->id(), $this->downtimeClass());
    }

    public function id(): string
    {
        return 'MY.L4.IDENTIFIER_LENGTH';
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

            if ($bare !== '' && IdentifierLength::exceeds($bare, IdentifierLength::MYSQL_CHARACTERS, false)) {
                $over[$bare] = true;
            }
        }

        foreach ($statement->keyColumns as $column) {
            $bare = IdentifierLength::bareName($column);

            if ($bare !== '' && IdentifierLength::exceeds($bare, IdentifierLength::MYSQL_CHARACTERS, false)) {
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
        return 'The identifier `'.$name.'` is over MySQL\'s 64-character limit, so the server refuses this '
            .'statement with ERROR 1059 and the deploy stops here.';
    }
}
