<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Agent\Remediation\RemediationValidator;
use Pushery\SQLens\Audit\ServerLifetime;
use Pushery\SQLens\Contracts\JudgesSchemaObjects;
use Pushery\SQLens\Contracts\JudgesTheServerItRunsOn;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Turns a catalog rule's verdicts into findings — once, for every base that has catalog subjects.
 *
 * Two bases reach a schema object now: {@see AbstractCatalogRule}, for a rule that only ever
 * answers from a catalog, and {@see AbstractSafetyRule}, for a lint rule that ALSO answers from one
 * ({@see JudgesSchemaObjects}). Letting each build its own finding would
 * be the second code path this package keeps refusing: the two would drift on the location shape,
 * on which metadata is stamped, or on how an undetermined verdict is carried — and the drift would
 * be invisible, because each half looks correct on its own.
 *
 * It takes the whole {@see Rule} rather than a dozen arguments. Everything a finding needs about
 * the rule is already on that contract, and passing the rule means a metadata field added later
 * cannot be forgotten here.
 */
final readonly class CatalogVerdicts
{
    /**
     * @param  list<RuleVerdict>  $verdicts
     * @return list<Finding>
     */
    public static function toFindings(array $verdicts, Rule $rule, SchemaObject $object): array
    {
        $verdicts = self::withoutTheFixturesVerdict($verdicts, $rule, $object);

        // Asked ONCE per object rather than once per verdict: the material is about the object, and
        // a rule that flags twice attaches the same template twice rather than building it twice.
        $payload = self::remediationFor($rule, $object);

        return array_map(
            static fn (RuleVerdict $verdict): Finding => self::withMaterial(self::finding($verdict, $rule, $object), $payload),
            $verdicts,
        );
    }

    /**
     * A flag about a server the project declared disposable, answered as not applicable instead.
     *
     * ## Why here and not inside the rules
     *
     * This is the one place that holds all three facts at once — the verdicts, the rule that reached
     * them, and the subject carrying the project's declaration. Pushed into the rules it would be
     * the same five lines in four base classes, and the interesting thing about those five lines is
     * that they must agree; four copies of a predicate that decides whether a security check speaks
     * is the shape {@see TouchedTables} exists to prevent one directory over.
     *
     * ## Only a FLAG is rewritten, and the three other outcomes are left alone
     *
     * An undetermined verdict about a disposable server is still undetermined — the reading failed,
     * and saying "not applicable" would answer a question nobody managed to ask. A pass stays a
     * pass. And a rule that said nothing gets nothing added: twenty lines announcing checks that
     * found nothing anyway is the noise this package's own authentication family already refuses
     * ("six rules repeating one fact is five repetitions of it").
     *
     * That last one is a real trade and not a free one, so it is written down rather than left to be
     * rediscovered: on a disposable server a reader cannot tell a check that passed from one that
     * did not apply, UNLESS it would have flagged. Where it would have, the finding says so in full.
     * Where it would not, nothing is withheld from the reader that the check itself established.
     *
     * @param  list<RuleVerdict>  $verdicts
     * @return list<RuleVerdict>
     */
    private static function withoutTheFixturesVerdict(array $verdicts, Rule $rule, SchemaObject $object): array
    {
        if (! $rule instanceof JudgesTheServerItRunsOn) {
            return $verdicts;
        }

        if (! ServerLifetime::declared($object->context()->serverLifetime)->isDisposable()) {
            return $verdicts;
        }

        return array_map(
            static fn (RuleVerdict $verdict): RuleVerdict => self::isFlag($verdict)
                ? RuleVerdict::notApplicable(
                    sprintf(
                        'this project declared sqlens.security.server.lifetime as disposable, so %s describes a '
                        .'fixture this job creates and destroys rather than a deployment anybody operates. The '
                        .'schema is judged here exactly as it would be anywhere; this server fact is judged by '
                        .'sqlens:predeploy, on the host that will actually be operated.',
                        $rule->serverSubjectJudged(),
                    ),
                    NotApplicableReason::ServerIsDisposable,
                )
                : $verdict,
            $verdicts,
        );
    }

    /**
     * Whether this verdict is the one that would BLOCK — a report of something wrong.
     *
     * Spelled as the absence of the other three rather than as a field, because that is how
     * {@see RuleVerdict} is built: a flag is the verdict with no reason attached and no pass flag
     * set. Asking it here keeps the knowledge in one place instead of widening the verdict's public
     * surface for one caller.
     */
    private static function isFlag(RuleVerdict $verdict): bool
    {
        return ! $verdict->isPass && ! $verdict->isUndetermined() && ! $verdict->isNotApplicable();
    }

    /**
     * The second remediation seam's ONE caller — the catalog counterpart of `CaptureFindingCollector`.
     *
     * One, and an architecture arm holds it there. On the lint side the number of callers grew from
     * one to three, and the unspoken precondition — "a rule is only asked about something it
     * reported" — broke silently when it did. Here the precondition is written on the contract and
     * the call site is single, which is the pair that keeps it true.
     *
     * ⚠️ Asked with the OBJECT, never with a statement. That is the whole reason the second contract
     * exists: {@see ProvidesRemediation} guarantees its placeholders come from a canonicalized
     * statement, and a catalog rule has none — so widening that seam would have made its guarantee
     * conditional rather than adding a case to it.
     */
    private static function remediationFor(Rule $rule, SchemaObject $object): ?RemediationPayload
    {
        return $rule instanceof ProvidesSchemaObjectRemediation
            ? $rule->remediationForObject($object)
            : null;
    }

    /**
     * The finding, carrying its material — or carrying why it does not.
     *
     * The only place a payload reaches a catalog finding, which is what makes the validator
     * unbypassable rather than merely available. A refusal never touches the finding itself: the
     * rule looked at the object and was right about it, and downgrading a real verdict over our own
     * defective template would hide a problem behind a second one.
     *
     * The validator is constructed here rather than injected because it is structural — no
     * database, no network, no clock, by its own contract — so there is nothing about it a caller
     * could need to vary, and a parameter would be a seam with one possible value.
     */
    private static function withMaterial(Finding $finding, ?RemediationPayload $payload): Finding
    {
        if (! $payload instanceof RemediationPayload) {
            return $finding;
        }

        $refusal = new RemediationValidator()->refusalFor($payload);

        return $refusal === null
            ? $finding->withRemediation($payload)
            : $finding->withRemediationRefusal($refusal);
    }

    /**
     * Where a catalog finding points: an instance and an object, never a file and a line.
     *
     * Every catalog reader stamps the source connection onto the context at construction, so an
     * object that came from a reading always carries one. The driver name stands in only for a
     * context built by hand — a subject that came from no reading at all.
     */
    private static function location(SchemaObject $object): Location
    {
        return Location::inCatalog(
            $object->context()->driver,
            $object->context()->connection ?? $object->context()->driver,
            $object->qualifiedName,
            $object->type,
        );
    }

    private static function finding(RuleVerdict $verdict, Rule $rule, SchemaObject $object): Finding
    {
        return self::stamped(self::bare($verdict, $rule, $object), $rule);
    }

    /**
     * The rule's declared downtime class, put on the finding.
     *
     * It was missing entirely: a catalog rule could DECLARE a class and no finding ever carried it,
     * so the field was metadata nobody received. The lint side stamps it through its own path, which
     * is why the gap survived — a value present in the registry export and absent from the report is
     * exactly the kind of difference nobody notices until a consumer branches on it.
     *
     * Applied to every outcome, not only a failure: what the FIX would cost does not depend on
     * whether this particular reading could decide.
     */
    private static function stamped(Finding $finding, Rule $rule): Finding
    {
        $class = $rule->downtimeClass();

        return $class instanceof DowntimeClass ? $finding->withDowntimeClass($class) : $finding;
    }

    private static function bare(RuleVerdict $verdict, Rule $rule, SchemaObject $object): Finding
    {
        $reason = $verdict->undeterminedReason;
        $location = self::location($object);

        if ($verdict->isPass) {
            // The one route from a catalog rule to a PASS finding. It exists because "the risk is
            // structurally excluded" is an answer, and the alternative — staying silent — is
            // indistinguishable from a rule that never ran.
            return Finding::pass(
                $rule->id(),
                $rule->messagePrefix(),
                $verdict->message,
                $location,
                $rule->category(),
                $rule->level(),
                $rule->stability(),
                $rule->documentationUrl(),
                $object->context(),
                $verdict->severity ?? $rule->severity(),
            );
        }

        if ($verdict->notApplicableReason instanceof NotApplicableReason) {
            // The one route from a catalog rule to a NOT-APPLICABLE finding. It exists for the same
            // reason the pass route above does, one step further out: staying silent is
            // indistinguishable from a rule that never ran — and here the rule genuinely did not,
            // because there was nothing on this engine for it to look at.
            return Finding::notApplicable(
                $rule->id(),
                $rule->messagePrefix(),
                $verdict->message,
                $verdict->notApplicableReason,
                $location,
                $rule->category(),
                $rule->level(),
                $rule->stability(),
                $rule->documentationUrl(),
                $object->context(),
                $verdict->severity ?? $rule->severity(),
            );
        }

        if ($reason instanceof UndeterminedReason) {
            return Finding::undetermined(
                $rule->id(),
                $rule->messagePrefix(),
                $verdict->message,
                $reason,
                $location,
                $rule->category(),
                $rule->level(),
                $rule->stability(),
                $rule->documentationUrl(),
                $object->context(),
                $verdict->severity ?? $rule->severity(),
            );
        }

        return Finding::fail(
            ruleId: $rule->id(),
            messagePrefix: $rule->messagePrefix(),
            message: $verdict->message,
            location: $location,
            category: $rule->category(),
            level: $rule->level(),
            stability: $rule->stability(),
            documentationUrl: $rule->documentationUrl(),
            context: $object->context(),
            severity: $verdict->severity ?? $rule->severity(),
        );
    }
}
