<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Severity\Severity;

/**
 * The machine fence that keeps a rule with incomplete or ambiguous metadata out
 * of the catalog. It runs over the whole registry, so every new
 * rule is checked automatically — rule ids, message prefixes and documentation
 * URLs are public API from 1.0, and this is what stops one shipping without them.
 *
 * Uniqueness is not re-checked here: RuleRegistry already rejects a duplicate id
 * at build, so any registry handed to the audit is already unique.
 *
 * Severity is required for a severity-gated category (security/privacy) and
 * OPTIONAL for the rest — a safety rule may carry a severity (the statistics
 * escalation path, added later) without being forced to, and without bypassing the level gate.
 * There is deliberately no rule forbidding a non-security rule a severity.
 *
 * The per-item checks live in `fieldViolations()` because the rule contract is
 * not the only thing that publishes this metadata: pre-scan detectors carry the
 * same fields without being rules, and a second copy of these four checks would
 * be a second definition of what "complete metadata" means.
 */
final class RuleMetadataAudit
{
    /**
     * Every metadata violation in the registry as a human-readable line; an empty
     * list means every rule is well-formed. Version window and deprecation are
     * guaranteed present by the contract, so their absence is unrepresentable.
     *
     * @return list<string>
     */
    public static function violations(RuleRegistry $registry): array
    {
        $violations = [];

        foreach ($registry->all() as $rule) {
            foreach (self::fieldViolations(
                'rule',
                $rule->id(),
                $rule->category(),
                $rule->severity(),
                $rule->messagePrefix(),
                $rule->documentationUrl(),
            ) as $violation) {
                $violations[] = $violation;
            }
        }

        return $violations;
    }

    /**
     * The metadata invariants themselves, over plain field values.
     *
     * @param  string  $kind  what the item is called in the message ("rule",
     *                        "pre-scan detector") — the finding has to name the
     *                        thing a maintainer has to go and fix
     * @return list<string>
     */
    public static function fieldViolations(
        string $kind,
        string $id,
        Category $category,
        ?Severity $severity,
        string $messagePrefix,
        string $documentationUrl,
    ): array {
        $violations = [];

        if (! RuleIdFormat::matches($id)) {
            $violations[] = sprintf('%s id "%s" does not match the naming scheme', $kind, $id);
        }

        if ($messagePrefix === '') {
            $violations[] = sprintf('%s "%s" has an empty message prefix', $kind, $id);
        }

        if ($documentationUrl === '') {
            $violations[] = sprintf('%s "%s" has an empty documentation url', $kind, $id);
        }

        if ($category->usesSeverityGate() && ! $severity instanceof Severity) {
            $violations[] = sprintf(
                '%s "%s" is in the %s category but declares no severity',
                $kind,
                $id,
                $category->value,
            );
        }

        return $violations;
    }
}
