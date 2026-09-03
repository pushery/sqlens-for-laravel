<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use LogicException;
use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * `CAP.L0.UNDETERMINED_CAPTURE` — the capture could not conclude for a migration,
 * for a named reason that is NOT a static pre-scan flag.
 *
 * This is the "no silent green" backstop of the capture path. A migration whose
 * capture came back undetermined — a file the scanner could not parse, a statement
 * the canonicalization layer rejected, a shadow session that hit its own timeout —
 * carries a reason but no SQL. Without this rule that migration would contribute no
 * finding at all and vanish from the run, which is exactly the silent green the tool
 * forbids: a migration the run could not check must SAY so, three-valued, not be
 * counted as clean.
 *
 * **The boundary this rule must not cross.** It fires only on an undetermined result
 * with NO pre-scan hits. A migration the static pre-scan flagged is already
 * undetermined, but its answer is the specific `CAP.PRESCAN.*` hits it was flagged
 * for — each individually addressable in a report and a baseline — so those are
 * reported as their own findings and this rule steps aside, or the same migration
 * would be reported twice under two different ids. This rule is the reason WITHOUT a
 * hit: the capture layer's own undetermined outcomes, named but not located to a line.
 *
 * The specific reason is preserved on the finding's status (and so in the run's
 * per-reason counts); the rule id groups them as one addressable family, the reason
 * axis keeps them apart.
 */
final readonly class UndeterminedCaptureRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.UNDETERMINED_CAPTURE';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::for(
            self::RULE_ID,
            'sqlens.lint',
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function up(): void
                {
                    // A binding the substitution layer cannot represent, or a statement
                    // the canonicalization rejects, leaves the capture undetermined — the
                    // run could not check this migration, and says so rather than passing it.
                    DB::statement('create table t (c '.$unrepresentable.')');
                }
                PHP,
            <<<'PHP'
                public function up(): void
                {
                    Schema::create('users', function (Blueprint $table): void {
                        $table->id();
                        $table->string('email');
                    });
                }
                PHP,
        );
    }

    public function appliesTo(CaptureResult $result): bool
    {
        // Undetermined, but not the pre-scan's doing: a pre-scan-flagged migration is
        // reported through its own CAP.PRESCAN hits, so this rule leaves it alone and
        // the two states never both report the same migration.
        return $result->isUndetermined() && $result->preScanHits === [];
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        // An undetermined result always carries a reason (the type enforces it at
        // construction) — the throw guards that invariant rather than inventing one.
        $reason = $result->reason ?? throw new LogicException('An undetermined capture result without a reason is unconstructible.');

        return Finding::undetermined(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The migration %s could not be captured and is reported as undetermined, not passed: %s The run checked nothing for this migration.',
                $result->migrationClass,
                $reason->description(),
            ),
            $reason,
            Location::inMigration(
                $result->file,
                $result->migrationClass,
                0,
                $result->section->direction(),
                $projectRoot,
            ),
            $this->metadata()->category,
            $this->metadata()->level,
            $this->metadata()->stability,
            $this->metadata()->documentationUrl,
            $context,
        );
    }
}
