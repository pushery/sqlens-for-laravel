<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The shape every "this line of pg_hba.conf is dangerous" rule has.
 *
 * Six of them exist, and they differ in one thing: which property of a line is the problem. What they
 * share is everything that is easy to get subtly wrong, and getting it wrong five times in five files
 * is how a suite ends up disagreeing with itself about one server:
 *
 * - **A line the server could not parse.** It authenticates nobody, so its fields are the empty ones
 *   PostgreSQL left behind. Judging them is wrong in both directions at once: a `trust` on a broken
 *   line lets nobody in, so flagging it invents a hole — and the restriction the line was meant to
 *   impose is not in force, so clearing it invents a wall. Every rule but {@see HbaParseErrorRule}
 *   therefore answers `undetermined` and points at the one rule whose whole subject the broken line
 *   is.
 * - **A line that came back half-read.** Distinct from the above and from a refusal: the line is here
 *   and part of it is missing, so a verdict about the missing part is the silent green in miniature.
 * - **An engine that has no such file.** MySQL produces no HBA subjects and reports
 *   `hba_supported => false`, so the six rules stay quiet there without any of them knowing what
 *   engine it is. That is a property of the data rather than a driver check somebody has to remember.
 *
 * ## What this base deliberately does NOT handle: the refusal
 *
 * `pg_hba_file_rules` is a VIEW over a superuser-only FUNCTION, and `pg_read_all_settings` is NOT enough to read it — measured on PostgreSQL 18.4: a role holding `pg_read_all_settings` gets `permission denied for function pg_hba_file_rules`, and `has_function_privilege` says `f`. Only superuser, or a role that has been granted EXECUTE on that function explicitly (`GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO …`, measured: 6 rows afterwards). On a managed instance that refusal is the normal case rather
 * than a fault. It produces no rule subjects at all
 * — but it is NOT silent, because the reading carries a named skip that the audit runner turns into
 * `SEC.SKIPPED.PG.HBA`. A rule that also spoke there would report one refusal seven times over. The
 * state that genuinely has nobody to report it is a reading that SUCCEEDED and returned nothing, and
 * that one has a hook below.
 *
 * ## Why they all sit at level 0 with a severity of their own
 *
 * A security finding is weighed on the RISK axis. Its level says only "no run excludes it", and a
 * project wanting fewer security findings raises `security.min_severity` — one dial, stated once,
 * rather than a level that would quietly take the whole category with it. It is also why an
 * escalation in this family is a second RULE rather than a variable severity: severity is metadata on
 * the rule, so `trust` over the network and `trust` on a Unix socket are two ids, not one id with a
 * conditional.
 */
abstract class AbstractHbaRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Two, and the second is not an oversight: the family judges the LINES, and one member also reads
     * the reading's own state off a role subject to report a reading that came back empty.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::HbaRule, SchemaObjectType::Role];
    }

    /**
     * Level 0 across the family, for the reason in the class docblock: the severity axis carries the
     * weight, so the level exists only to keep the rule in every run.
     */
    public function level(): Level
    {
        return Level::Capturable;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /**
     * What this rule says about a line it objects to, or an empty list when it does not object.
     *
     * @return list<RuleVerdict>
     */
    abstract protected function judgeRule(SchemaObject $object): array;

    /**
     * Whether this rule has anything to say about a line the SERVER could not parse.
     *
     * False for five of the six: the fields they read are the ones PostgreSQL left empty, so there is
     * nothing to judge and the honest answer is `undetermined`. True only for
     * {@see HbaParseErrorRule}, whose subject IS the broken line.
     */
    protected function judgesBrokenLines(): bool
    {
        return false;
    }

    /**
     * Whether this rule is the one that reports the family's not-applicable on an engine with no
     * `pg_hba.conf` at all.
     *
     * Same shape and same reason as {@see self::judgeEmptyReading()}: the fact belongs to the FAMILY,
     * not to each member, so one rule carries it and five stay quiet. Which one is arbitrary in
     * principle and deliberate in practice — {@see HbaParseErrorRule} already owns the family's
     * "nothing here was checked" statement for the empty-reading case, and splitting the two across
     * different rules would mean a reader learns the same thing from a different id depending on why.
     */
    protected function speaksForTheEngineGap(): bool
    {
        return false;
    }

    /**
     * What this rule says when the reading SUCCEEDED and returned no rules at all.
     *
     * Default: nothing, and exactly one rule in the family overrides it — one `undetermined` per run
     * is the right number for that state, and six would be five repetitions of one fact.
     *
     * The state is genuinely contradictory rather than merely unusual: a server with no host-based
     * authentication rules accepts no connections, and this audit arrived over one. So it is either a
     * reading that lost its rows without noticing or a server nobody can reach — and both deserve
     * saying out loud.
     *
     * @return list<RuleVerdict>
     */
    protected function judgeEmptyReading(SchemaObject $object): array
    {
        return [];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type === SchemaObjectType::Role) {
            return $this->judgeReadingState($object);
        }

        if ($object->type !== SchemaObjectType::HbaRule) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('%s could not be read in full, so what it authorizes is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($object->getBool('is_broken') === true && ! $this->judgesBrokenLines()) {
            return [RuleVerdict::undetermined(
                sprintf(
                    'PostgreSQL could not parse %s, so the fields this check reads are the empty ones it left '
                    .'behind — this line authorizes nobody, and the restriction it was meant to impose is not in '
                    .'force. See SEC.AUTH.HBA_PARSE_ERROR, which reports the line itself.',
                    $object->qualifiedName,
                ),
                UndeterminedReason::HostAuthRuleUnparsable,
            )];
        }

        return $this->judgeRule($object);
    }

    /**
     * The one thing the family says on a run that produced no lines to judge.
     *
     * Attached to the connecting role's subject, because that is the only subject every run has: a
     * reading with no rules produces no HBA subjects, so a rule with nothing to judge would report
     * nothing — and "no dangerous authentication rules" is precisely what that would read as.
     *
     * @return list<RuleVerdict>
     */
    private function judgeReadingState(SchemaObject $object): array
    {
        // MySQL has no host-based authentication file in any version — so there is nothing here for
        // these checks to look at, and that is a different statement from "checked and fine".
        //
        // Exactly ONE rule in the family says it, on the same terms as judgeEmptyReading() below: six
        // rules repeating "this engine has no such file" is five repetitions of one fact, and the
        // earlier reading of this branch — stay silent, or somebody goes looking for a file their
        // server does not have — was right about the noise and wrong about the silence. A reader who
        // sees nothing concludes the authentication rules were checked.
        // Gated on `connection_role` as well as on the one speaking rule: the flag rides every ROLE
        // subject and a server has several, so without it the family would say its one fact once per
        // account instead of once per run.
        if ($object->getBool('hba_supported') !== true) {
            return $this->speaksForTheEngineGap() && $object->getBool('connection_role') === true
                ? [RuleVerdict::notApplicable(
                    'this server is MySQL, which has no host-based authentication file at all, so none of the '
                    .'SEC.AUTH.HBA_* checks has anything here to look at. Reported rather than left silent, because '
                    .'an absent finding reads as a check that passed. How MySQL authenticates is judged by its own '
                    .'rules, not by these.',
                    NotApplicableReason::EngineLacksConstruct,
                )]
                : [];
        }

        // The refusal belongs to SEC.SKIPPED.PG.HBA, which the reading's own skip already produces.
        // Speaking here as well would report one refusal twice, from two mechanisms that would then
        // have to be kept in step forever.
        if ($object->getBool('hba_readable') !== true) {
            return [];
        }

        if ($object->getBool('connection_role') !== true || ($object->getInt('hba_rule_count') ?? 0) > 0) {
            return [];
        }

        return $this->judgeEmptyReading($object);
    }
}
