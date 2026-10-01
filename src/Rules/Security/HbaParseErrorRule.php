<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A line of `pg_hba.conf` that PostgreSQL itself could not parse.
 *
 * The server reports it in `pg_hba_file_rules` with an `error` and no fields. That view reads the
 * file as it is on disk, and a file holding such a line is not loaded at all: a reload is refused as a
 * whole and the server keeps the rules it loaded before, and a start fails. Measured on 18.4 with a
 * throwaway cluster, where the log said `pg_hba.conf was not reloaded` and `could not load
 * pg_hba.conf`. So neither the broken line nor any other edit in the file is in force, and the server
 * may be running on rules the file no longer shows.
 *
 * ## Why it is a finding rather than a read error
 *
 * Nothing went wrong with the reading. The server is stating, in its own words, that one of its
 * authentication rules is broken — which is a fact about the server's security posture and belongs in
 * a report. Raising it as an exception would lose it; treating the line as absent would silently
 * agree with the server.
 *
 * ## The counterpart in the other five rules
 *
 * They answer `undetermined` on a broken line and point here, rather than judging the empty fields
 * PostgreSQL left behind. That split is what keeps a broken `trust` line from being either falsely
 * flagged (it lets nobody in) or falsely cleared (its intended restriction is gone).
 */
final class HbaParseErrorRule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_PARSE_ERROR';
    }

    /**
     * `medium`: the file says something the server is not doing, and where that lands depends on what
     * the following lines allow. It is a configuration integrity failure rather than a known opening,
     * so it sits below the method rules and above nothing at all.
     */
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** The one rule in the family whose subject IS the broken line. */
    #[Override]
    protected function judgesBrokenLines(): bool
    {
        return true;
    }

    /**
     * This rule carries the family's not-applicable, for the same reason it carries its
     * empty-reading undetermined: both are statements about the FAMILY rather than about one check,
     * and a reader should not learn the same fact from a different rule id depending on why.
     */
    #[Override]
    protected function speaksForTheEngineGap(): bool
    {
        return true;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getBool('is_broken') !== true) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'PostgreSQL could not parse %s and reported: %s. A file holding such a line is not loaded at '
            .'all: a reload is refused and the server keeps the rules it loaded before, and a restart does '
            .'not start the server. So neither this line nor any other edit in the file is in force. Fix '
            .'the line and reload the configuration (SELECT pg_reload_conf()), then re-read '
            .'pg_hba_file_rules to confirm the error is gone.',
            $object->qualifiedName,
            $object->getString('parse_error') ?? 'no reason given',
        ))];
    }

    /**
     * The family's one statement about a reading that succeeded and returned nothing.
     *
     * It lives here because this rule is the one about the FILE rather than about a line in it, and
     * because the state it describes is the same class of problem: the file, as the server understood
     * it, does not say what somebody thinks it says.
     *
     * `undetermined` rather than a finding, because the explanations are outside what this reading
     * can distinguish. A server that had loaded no authentication rules would have refused this very
     * connection. The view reads the file, though, and a file without entries is refused on reload
     * while the server keeps the rules it had, measured on 18.4. So either the file holds no entries,
     * or the rows were lost on the way here.
     *
     * @return list<RuleVerdict>
     */
    #[Override]
    protected function judgeEmptyReading(SchemaObject $object): array
    {
        return [RuleVerdict::undetermined(
            'pg_hba_file_rules answered without refusing and returned no rules at all. A PostgreSQL that '
            .'had loaded no host-based authentication rules accepts no connections, and this audit arrived '
            .'over one. The view reads the file on disk, so it may be a file without entries, which the '
            .'server refuses to load while it keeps the rules it had. Nothing about how this server '
            .'authenticates has been checked — confirm the file the server is actually reading (SHOW '
            .'hba_file) before reading this run as clean.',
            UndeterminedReason::CatalogReadingImplausible,
        )];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the FILE as it is on disk, through the server\'s own parse of it, which is not necessarily what the server has loaded: an edit that has not been reloaded is judged as if it were in force, and a reload the server refused leaves its previous rules running where this reading cannot see them',
            'cannot say what the broken line INTENDED, and deliberately does not guess. What it does say is the thing that matters either way: whatever restriction was meant is not in force, because the server did not load it',
            'the line is reported, never its content. A malformed line frequently contains the thing somebody was in the middle of writing, and echoing it into a report would publish it further',
        ];
    }
}
