<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\Advisory\EolData;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Advisory\PatchAssessment;
use Pushery\SQLens\Security\Advisory\PatchLevelEvaluator;
use Pushery\SQLens\Security\Advisory\PatchVerdict;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * What the two patch-currency rules share: finding the version, and judging it offline.
 *
 * ## The subject is a server variable, which is why these are SEC.CFG
 *
 * PostgreSQL reports its version through the `server_version` GUC and MySQL through the `version`
 * system variable, so both arrive as ordinary `Setting` subjects on the same path every other
 * server-baseline rule uses. Nothing had to be added to the readers: they fetch the whole of
 * `pg_settings` and `SHOW GLOBAL VARIABLES` rather than a curated list.
 *
 * That is also the answer to which area these belong in. The scheme puts a rule where its SUBJECT
 * is, and the subject here is literally a server variable — the same reader who fixes
 * `SEC.CFG.TLS_DISABLED` is the one who upgrades a server past its support window.
 *
 * ## Never the network
 *
 * The verdict comes from a bundled file. A patch-currency check that had to reach the network would
 * be unusable on a runner without egress and would answer the same question differently on two
 * days — so what this cannot know, it says it cannot know.
 */
abstract class AbstractPatchLevelRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * The server variables that carry a version, by driver.
     *
     * Matched on the NAME rather than resolved from the run's driver, and that is deliberate: a
     * subject reaches a rule with its own name attached, so keying off the name needs no second
     * source of truth about which engine is being read — and a rule that guessed the engine could
     * be wrong in a way the subject in front of it plainly is not.
     *
     * @var array<string, string> variable name => the product key in the end-of-life data
     */
    private const array VERSION_VARIABLES = [
        'server_version' => 'postgresql',
        'version' => 'mysql',
    ];

    public function __construct(
        string $projectRoot,
        private readonly EolRepository $advisories,
        /**
         * Today, as an ISO-8601 date.
         *
         * Injected rather than read from the clock inside the rule, because a support window closes
         * on a date and a rule that read the clock would give two answers to one database across
         * midnight — with nothing in the report to say which side it was on.
         */
        private readonly string $today,
        private readonly PatchLevelEvaluator $evaluator = new PatchLevelEvaluator,
    ) {
        parent::__construct($projectRoot);
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Setting];
    }

    /** @return non-empty-list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** Whether this rule speaks about the given verdict at all. */
    abstract protected function judges(PatchVerdict $verdict): bool;

    /** The finding, once the shared half has established that this rule is the one to report it. */
    abstract protected function flag(PatchAssessment $assessment): string;

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Setting) {
            return [];
        }

        $product = self::VERSION_VARIABLES[$object->qualifiedName] ?? null;

        if ($product === null) {
            return [];
        }

        $reported = $object->getString('server_value');

        // The variable is present but the server withheld its value. Reported rather than dropped:
        // "no version" and "a supported version" must not look the same to a reader, and only one
        // of them is a reason to stop worrying.
        if ($reported === null || $reported === '') {
            return [RuleVerdict::undetermined(
                sprintf(
                    'this server did not report a value for %s, so its release series could not be '
                    .'established and nothing was compared against the support dates. That is not the '
                    .'same as being in support: it is a reading that did not happen.',
                    $object->qualifiedName,
                ),
                UndeterminedReason::UnknownServerVersion,
            )];
        }

        $lookup = $this->advisories->lookup();

        if (! $lookup->data instanceof EolData) {
            // The one place this rule reports about the DATA rather than about the server, and it
            // says so: an operator whose advisory file is missing has a different job from one whose
            // server is out of support, and a message that blamed the server would send them to the
            // wrong one.
            return [RuleVerdict::undetermined(
                sprintf(
                    'the server reports %s, and nothing was compared against it because %s. A version '
                    .'with nothing to hold it against is not a version in support — the check did not '
                    .'run, and this is it saying so.',
                    $reported,
                    (string) $lookup->reason,
                ),
                UndeterminedReason::AdvisoryDataUnavailable,
            )];
        }

        $assessment = $this->evaluator->evaluate($reported, $product, $lookup->data, $this->today);

        if (! $this->judges($assessment->verdict)) {
            return [];
        }

        return $assessment->verdict->isFinding()
            ? [RuleVerdict::flag($this->flag($assessment))]
            : [RuleVerdict::undetermined($this->gap($assessment), $this->reasonFor($assessment->verdict))];
    }

    /**
     * The sentence for a verdict that is a gap in the DATA rather than a finding about the server.
     *
     * Shared, because all three gaps say the same thing in the end — the comparison did not happen —
     * and differ only in why. Three hand-written near-identical paragraphs would drift, and the
     * drift would show up as one of them quietly losing the sentence that keeps it from reading
     * like a pass.
     */
    private function gap(PatchAssessment $assessment): string
    {
        $why = match ($assessment->verdict) {
            PatchVerdict::PatchLevelUnknown => sprintf(
                'this data records no patch level for the %s series, so how far behind the server is '
                .'could not be established. The bundled copy deliberately carries none: a patch number '
                .'shipped inside a package is wrong within a month of any release, and a wrong "latest" '
                .'produces either invented findings or invented confidence. Refresh the advisory data '
                .'to answer this',
                (string) $assessment->cycle,
            ),
            PatchVerdict::CycleUnknown => sprintf(
                'this data has no entry for the %s series at all — the server is either newer than the '
                .'file or older than anything it records, and neither is a verdict this can reach. A '
                .'new major is not out of support, and an ancient one is not fine',
                (string) $assessment->cycle,
            ),
            default => sprintf(
                'the version string "%s" could not be read as a release series, so there was nothing '
                .'to look up',
                $assessment->reported,
            ),
        };

        return sprintf('the server reports %s, and %s (%s).', $assessment->reported, $why, $assessment->provenance());
    }

    private function reasonFor(PatchVerdict $verdict): UndeterminedReason
    {
        return match ($verdict) {
            // The data was read and simply does not carry the answer — a property of the artifact,
            // which is exactly what this reason names.
            PatchVerdict::PatchLevelUnknown, PatchVerdict::CycleUnknown => UndeterminedReason::AdvisoryDataUnavailable,
            default => UndeterminedReason::UnknownServerVersion,
        };
    }
}
