<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Security\SecretLiteralMask;
use Pushery\SQLens\Subjects\CaptureMode;
/**
 * `CAP.L0.PRETEND_ERROR` — the migration threw while it was being captured under
 * pretend.
 *
 * This is the second half of the level-0 assurance "the migration runs cleanly
 * under pretend". The captor does not let a throwing migration crash the whole
 * run; it records the failure with the exception message and moves on. This rule
 * is what turns that recorded failure into a reported finding, so a migration
 * that could not even simulate is never lost in the noise of a run.
 *
 * **Different trigger, different family member.** `NotCapturableRule` fires on a
 * migration that captured SUCCESSFULLY but emitted nothing; this one fires on a
 * migration whose capture FAILED with a throw. The two are mutually exclusive by
 * construction — a capture result is either a pass or a fail, never both — so
 * they never double-report, and each names a distinct problem the other would
 * mislabel. A pre-scan-flagged migration is `undetermined`, not a fail, and
 * never reaches either.
 *
 * The exception message rides on the capture result (the captor stored it,
 * because the exception is gone by the time a rule runs), so the finding can
 * report WHY the pretend run failed without re-deriving anything.
 */
use Pushery\SQLens\Subjects\SubjectContext;

final readonly class PretendErrorRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.PRETEND_ERROR';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::for(
            self::RULE_ID,
            'sqlens.lint',
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function up(): void
                {
                    // A typo, a missing class, a bad call — this throws under pretend,
                    // so its SQL can never be captured and the migration cannot be linted.
                    Schema::create('users', fn (Blueprint $table) => $table->nonexistentType('x'));
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

    public function appliesTo(CaptureResult $result, SubjectContext $context): bool
    {
        // Pretend failures only — a shadow-mode failure is CAP.L0.MIGRATE_ERROR's,
        // and scoping by mode keeps the two from double-reporting or mislabeling
        // which mode a failure happened in.
        return $result->isFail() && $result->mode === CaptureMode::Pretend;
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        return Finding::fail(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The migration %s threw while being captured under pretend, so its SQL could not be linted: %s. Fix the error the migration raises; until it can run under pretend, no rule can see what it does.',
                $result->migrationClass,
                $this->detail($result, $projectRoot),
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

    /**
     * The exception message the captor recorded, made deterministic.
     *
     * Three things this guarantees. First, credentials are redacted: pretend still
     * runs the migration's read queries (Schema::hasTable, DB::select in up()), so a
     * connection-level failure — a bad password, an unreachable host — surfaces here
     * carrying host, user, and password, exactly like the shadow-side migrate error.
     * Second, determinism: the same error produces the same output on every machine.
     * The captor stores `getMessage()`, never the trace, so there is no stack to
     * strip — but an exception message can still embed the absolute path a file lived
     * at, which differs per checkout, so the project root is relativized out (AFTER
     * redaction, so a credential inside such a path is caught first). Third, the
     * fallback keeps the message honest (never an empty "…: .") on the rare failure
     * the captor recorded without a detail.
     */
    private function detail(CaptureResult $result, string $projectRoot): string
    {
        $detail = $result->failureDetail ?? 'the capture recorded no further detail';

        $detail = (new CredentialRedactor)->redact($detail);

        // ⚠️ TWO PASSES, AND THEY CATCH DIFFERENT THINGS. `CredentialRedactor` knows the values
        // this application CONFIGURED — it takes the connection's own host, user and password out
        // of the text. It cannot know a password somebody typed straight into a migration, because
        // that value appears in no configuration.
        //
        // `SecretLiteralMask` is the other half: it finds a secret by the SHAPE of the statement
        // (`PASSWORD '…'`, `IDENTIFIED BY '…'`) rather than by knowing its value. A database error
        // quotes the statement that failed, so a failed `CREATE ROLE … PASSWORD 'literal'` puts
        // that literal into this detail — and the package has a RULE for exactly that mistake, so
        // the report would name the problem and then print it.
        //
        // Only the agent reporter applied this mask, which left the console, JSON, SARIF and
        // GitHub-annotation surfaces carrying the value. The mask's own docblock already says why
        // it lives in the domain rather than in a reporter: "none of those has a redactor".
        $detail = SecretLiteralMask::in($detail);

        $root = rtrim($projectRoot, '/').'/';

        return str_replace($root, '', $detail);
    }
}
