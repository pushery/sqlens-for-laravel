<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Settings;

use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Security\Privacy\ProductionVerdict;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The condition on a finding whose value is only a problem on a production instance.
 *
 * ## Why it is shared rather than written per rule
 *
 * Two rules now need it and they describe the SAME server value from two angles — the general query
 * log as a credential leak and as personal data. Two copies of a three-valued environment check
 * would eventually disagree about what "cannot tell" means, and the disagreement would show as one
 * of them reporting a pass on a server the other called undetermined. Over one setting.
 *
 * ## The three answers, and why the third one carries the design
 *
 * Production lets the finding stand; not-production is a PASS WITH ITS SENTENCE; and unplaceable is
 * `undetermined`.
 *
 * That third value is the whole reason this is safe to apply to a security rule at all. The
 * tempting shape — "only report when the environment says production" — silences the rule on every
 * run that did not say, which is the common case for a first look at a real database. Here an
 * unplaceable environment is a FINDING rather than a silence, so the only thing that quiets the
 * rule is a project declaring, in its own `app.env`, that this is not production.
 *
 * The not-production answer is a pass rather than nothing for the same reason: "checked, and it
 * cannot expose anything here" and "this rule never ran" are different states of a report, and only
 * one of them tells a reader they are covered.
 *
 * ## Asked of a wrong value only
 *
 * The rules call this from `findingCondition()`, which runs after the value was judged a violation.
 * The three answers describe a value that WOULD be reported: the pass sentence says it is set, and
 * the undetermined says the environment decides. For `general_log = OFF` both would be false, and
 * the undetermined would fail a `ci` run over a server in its factory settings.
 */
trait JudgesProductionOnly
{
    /** What this rule would report if the environment were production — for the pass sentence. */
    abstract protected function environmentConcern(): string;

    /** The variable this rule judges, for every sentence below. */
    abstract public function settingVariable(): string;

    /**
     * The answer for a finding the value raised, or null when the environment is production and the
     * finding stands.
     */
    protected function productionCondition(SchemaObject $object, ?RunEnvironment $environment): ?RuleVerdict
    {
        $connection = $object->context()->connection;

        // No connection name at all. A migration read from disk genuinely has none, and the context
        // says so rather than inventing one; here it means the environment cannot be placed, which
        // is the same answer as an unplaceable name and reaches it by a different road.
        if ($connection === null || ! $environment instanceof RunEnvironment) {
            return RuleVerdict::undetermined(
                sprintf(
                    '%s is set, but this run could not establish whether it is looking at a '
                    .'production instance: %s only matters there, and reporting it anyway would '
                    .'state something about a server nobody placed.',
                    $this->settingVariable(),
                    $this->settingVariable(),
                ),
                UndeterminedReason::NotConfigured,
            );
        }

        return match ($environment->verdict($connection)) {
            ProductionVerdict::Production => null,

            ProductionVerdict::NotProduction => RuleVerdict::pass(sprintf(
                '%s is set, and %s — but this run is not looking at a production instance, so it '
                .'exposes nothing that needs protecting here.',
                $this->settingVariable(),
                $this->environmentConcern(),
            )),

            ProductionVerdict::Undetermined => RuleVerdict::undetermined(
                sprintf(
                    '%s is set, but nothing places this run as production or not — `app.env` is '
                    .'unset, carries a name this check does not recognize, or speaks for the '
                    .'application\'s own server while this connection reaches another, and the '
                    .'connection name says nothing either. Guessing "not production" would report '
                    .'a pass about a server that was never placed.',
                    $this->settingVariable(),
                ),
                UndeterminedReason::NotConfigured,
            ),
        };
    }
}
