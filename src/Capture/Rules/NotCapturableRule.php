<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * `CAP.L0.NOT_CAPTURABLE` — the capture ran to completion but produced no SQL to
 * lint.
 *
 * This is the lint suite's very lowest assurance made real: before any rule can
 * say anything about a migration's SQL, there has to BE SQL. A migration whose
 * `up()` emits nothing — an empty method, a method that calls no schema or DB
 * builder, or one whose every statement the canonicalization layer rejected —
 * comes out of the capture as a clean pass with an empty statement list. The
 * capture is right to call that honest (it captured successfully; there was
 * simply nothing), but at level 0 the lint suite does not let it pass silently:
 * a migration that contributes no SQL to a lint run is a migration the run never
 * actually checked, and "no silent green" means saying so.
 *
 * **The boundary this rule must not cross.** It fires ONLY on a successful,
 * empty capture. A migration the static pre-scan flagged is `undetermined`, not
 * an empty pass — the capture was never attempted — so it never reaches this
 * rule, and the two states can never overlap. A migration that threw under
 * pretend is a `fail` with a message, judged by `PretendErrorRule`, not this
 * one. This rule is exactly "tried, succeeded, got nothing".
 */
final readonly class NotCapturableRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.NOT_CAPTURABLE';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::for(
            self::RULE_ID,
            'sqlens.lint',
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function up(): void
                {
                    // Nothing here emits SQL — the lint run has nothing to check,
                    // and a migration that checks nothing should not read as clean.
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
        // Tried, succeeded, got nothing. A fail (it threw) or an undetermined (a
        // pre-scan flag, an unreadable file) is a different state with a different
        // rule, and reading either as "not capturable" would misname it.
        return $result->isPass() && $result->statementCount() === 0;
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        return Finding::fail(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The migration %s produced no SQL to lint. Its %s emits no schema or data change the capture could see, so the run checked nothing here — an empty migration is reported rather than passed silently. If the migration is intentionally empty, remove it; if it should change the schema, it is not doing so.',
                $result->migrationClass,
                $result->section->direction()->value.'()',
            ),
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
