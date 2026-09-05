<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Agent\Remediation\RemediationValidator;
use Pushery\SQLens\Contracts\JudgesSchemaObjects;
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
        // Asked ONCE per object rather than once per verdict: the material is about the object, and
        // a rule that flags twice attaches the same template twice rather than building it twice.
        $payload = self::remediationFor($rule, $object);

        return array_map(
            static fn (RuleVerdict $verdict): Finding => self::withMaterial(self::finding($verdict, $rule, $object), $payload),
            $verdicts,
        );
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
