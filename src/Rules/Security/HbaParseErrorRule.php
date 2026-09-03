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
 * The server reports it in `pg_hba_file_rules` with an `error` and no fields. The consequence is
 * quiet and asymmetric: the line does not authenticate anybody, so whatever restriction it was
 * written to impose is not in force — and the NEXT matching line decides who gets in instead. A file
 * whose author believes it contains a narrow rule may be running on the broad one below it.
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
            'PostgreSQL could not parse %s and reported: %s. The line authenticates nobody, so the '
            .'restriction it was written to impose is not in force and the next matching line decides who '
            .'connects instead. Fix the line and reload the configuration (SELECT pg_reload_conf()), then '
            .'re-read pg_hba_file_rules to confirm the error is gone.',
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
     * `undetermined` rather than a finding, because both explanations are outside what this reading
     * can distinguish — a server with genuinely no authentication rules would have refused this very
     * connection, so either the rows were lost on the way here or something stranger is true.
     *
     * @return list<RuleVerdict>
     */
    #[Override]
    protected function judgeEmptyReading(SchemaObject $object): array
    {
        return [RuleVerdict::undetermined(
            'pg_hba_file_rules answered without refusing and returned no rules at all, which cannot '
            .'describe this server: a PostgreSQL with no host-based authentication rules accepts no '
            .'connections, and this audit arrived over one. Nothing about how this server authenticates '
            .'has been checked — confirm the file the server is actually reading (SHOW hba_file) before '
            .'reading this run as clean.',
            UndeterminedReason::CatalogReadFailed,
        )];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads what the server has LOADED, not what is on disk — an edit made and not reloaded is invisible here, and so is one already written that has not taken effect yet',
            'cannot say what the broken line INTENDED, and deliberately does not guess. What it does say is the thing that matters either way: whatever restriction was meant is not in force, because the server did not load it',
            'the line is reported, never its content. A malformed line frequently contains the thing somebody was in the middle of writing, and echoing it into a report would publish it further',
        ];
    }
}
