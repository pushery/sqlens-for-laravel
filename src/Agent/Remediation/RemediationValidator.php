<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;

/**
 * The last thing that looks at a payload before a finding carries it.
 *
 * A half-filled fix template is more dangerous than none at all: an agent acting on `ALTER TABLE
 *  ADD CONSTRAINT  CHECK` — a statement whose substitution blanked what it could not fill — is
 * acting on something that reads like SQL and is not. The fill never writes that shape: a value it
 * was not given, or one that is empty, leaves its placeholder standing
 * ({@see RemediationStep::filled()}). What is checked here is what the fill cannot rule out, and a
 * payload that cannot be vouched for does not ship: the reason ships instead.
 *
 * ## What the type system already guarantees, and is therefore not checked here
 *
 * Enum-value validation and required-field validation are both already made by
 * the language: {@see RemediationPayload} is a readonly object whose `strategy` is a
 * {@see RemediationStrategy}, whose steps are {@see RemediationStep}s and whose kinds are
 * {@see RemediationStepKind}s. There is no way to construct one carrying `strategy: "concurrentley"`
 * or missing its `ruleId` — the constructor refuses. Writing those checks anyway would produce
 * branches no run can enter, which is worse than no branch: they would claim a guarantee and could
 * never be executed to prove it.
 *
 * What can go wrong is everything the constructor does not police, and each check below exists
 * because a specific mistake would produce it.
 *
 * ## The check first specified backwards, corrected against the built layer
 *
 * "No unresolved `{{…}}` in the result" would reject nearly every payload this package produces —
 * and rightly produces. A placeholder STANDS when its value is a decision rather than a fact: the
 * name of a column that does not exist yet, a collation, a batch size. Blanking those is the
 * failure described above, so demanding they be filled would enforce it.
 *
 * What is checked instead is that a placeholder is well formed — `{{name}}`, closed, named. A
 * substitution that went wrong leaves `{{tab`, `{{}}`, or `{{ table }}`, and those are the shapes a
 * reader cannot act on.
 *
 * ## Structural only
 *
 * No database, no network, no clock, no file outside the shipped schema. The same payload validates
 * the same way everywhere, which is what lets a refusal be a fact about the payload rather than
 * about the machine.
 */
final readonly class RemediationValidator
{
    /** The key prefix every refusal reason lives under — machine-findable, and translatable. */
    public const string REASON_PREFIX = 'sqlens::messages.remediation.invalid.';

    /** `{{name}}`: two braces, a lowercase snake_case name, two braces. Anything else is malformed. */
    private const string PLACEHOLDER = '/\{\{[a-z][a-z0-9_]*\}\}/';

    /** Any run of braces at all, so a MALFORMED one can be told from the absence of one. */
    private const string ANY_BRACES = '/\{\{|\}\}/';

    /**
     * The reason this payload must not ship, or null when it may.
     *
     * A single reason rather than a list, deliberately: the caller's only decision is ship-or-refuse,
     * and a list would invite a consumer to triage validator output instead of fixing the template
     * that produced it. The checks run in the order a reader would want them — the shape of the
     * whole thing first, then the steps, then the text inside them.
     */
    public function refusalFor(RemediationPayload $payload): ?string
    {
        if ($payload->steps === []) {
            // Zero steps reads, in a report, exactly like a payload somebody forgot to fill in —
            // which is the one thing a `strategy` value is supposed to distinguish itself from.
            return self::REASON_PREFIX.'no_steps';
        }

        if ($this->ordersAreNotContiguous($payload->steps)) {
            return self::REASON_PREFIX.'step_order';
        }

        if ($this->strategyDisagreesWithSteps($payload)) {
            return self::REASON_PREFIX.'none_carries_a_sequence';
        }

        // The two the SUBJECT makes checkable, and the reason they are refusals rather than
        // omissions at render time. A field that is merely meaningless for half the ground set is
        // still a field somebody reads: `downtime_class: online` on a state finding is a sentence
        // about a deploy that does not exist, and it is exactly as legible as a true one.
        if (! $payload->subject->carriesADowntimeClass() && $payload->downtimeClass instanceof DowntimeClass) {
            return self::REASON_PREFIX.'downtime_class_without_a_deploy';
        }

        if ($payload->subject === RemediationSubject::SchemaObject && $this->namesThisMigration($payload)) {
            return self::REASON_PREFIX.'this_migration_without_a_migration';
        }

        foreach ($payload->steps as $step) {
            if (! str_starts_with($step->noteKey, 'sqlens::messages.')) {
                // A note that is not a catalog key is a sentence this package already chose, in a
                // language it picked for somebody else. A key can be localized by whoever renders it,
                // and the payload stays the same bytes for every reader — which is what makes it
                // diffable and what makes it usable by a consumer whose language we do not know.
                return self::REASON_PREFIX.'note_key';
            }

            if ($this->hasMalformedPlaceholder($step->sqlTemplate) || $this->hasMalformedPlaceholder($step->laravelSnippet)) {
                return self::REASON_PREFIX.'placeholder';
            }
        }

        return null;
    }

    /**
     * Whether any step says "in this migration" — the one step kind a state finding cannot use.
     *
     * `SeparateMigration` is the right kind there and stays valid: the fix for a state is a new
     * migration. What cannot be true is a step that edits the migration at hand, because a catalog
     * rule was not handed one.
     */
    private function namesThisMigration(RemediationPayload $payload): bool
    {
        return array_any(
            $payload->steps,
            static fn (RemediationStep $step): bool => $step->kind === RemediationStepKind::MigrationStatement,
        );
    }

    /** Whether the payload may be carried by a finding. */
    public function passes(RemediationPayload $payload): bool
    {
        return $this->refusalFor($payload) === null;
    }

    /**
     * Steps numbered 1..n with no gap and no repeat.
     *
     * The order is what a reader executes by, so a gap is not cosmetic: step 4 following step 2
     * reads as "there was a step 3 and it is missing", which is a reader looking for material that
     * was never written.
     *
     * @param  list<RemediationStep>  $steps
     */
    private function ordersAreNotContiguous(array $steps): bool
    {
        $orders = array_map(static fn (RemediationStep $step): int => $step->order, $steps);

        return $orders !== range(1, count($steps));
    }

    /**
     * `strategy: none` claiming a sequence it says does not exist.
     *
     * The value means "looked at, and there is no safe standard sequence". A payload carrying SQL
     * under it is contradicting itself in the one field a reader trusts to tell a considered
     * conclusion from an absence — and the contradiction would be invisible in a report, because
     * both halves look correct on their own.
     */
    private function strategyDisagreesWithSteps(RemediationPayload $payload): bool
    {
        if ($payload->strategy !== RemediationStrategy::None) {
            return false;
        }

        return array_any(
            $payload->steps,
            static fn (RemediationStep $step): bool => $step->sqlTemplate !== null
                || $step->kind !== RemediationStepKind::ManualGate,
        );
    }

    /**
     * Braces that are not a well-formed placeholder.
     *
     * Every `{{` and every `}}` must belong to a well-formed placeholder. A single brace is free, so
     * the PHP of a snippet passes, closures and interpolation included, while two in a row are a
     * placeholder's: a snippet that closes two blocks on one line (`}});`) is refused, and none of
     * the package's templates writes one.
     */
    private function hasMalformedPlaceholder(?string $text): bool
    {
        if ($text === null) {
            return false;
        }

        // Remove every well-formed placeholder, then ask whether a `{{` or `}}` survived. What is
        // left can only be a broken one — an unclosed brace pair, an empty name, or a spaced name
        // that a substitution will never match.
        return preg_match(self::ANY_BRACES, (string) preg_replace(self::PLACEHOLDER, '', $text)) === 1;
    }
}
