<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Security\SecretLiteralMask;
use Pushery\SQLens\Subjects\CaptureMode;
/**
 * `CAP.L0.MIGRATE_ERROR` — the migration failed while it was being run for real
 * against the shadow database.
 *
 * This is the shadow counterpart to `CAP.L0.PRETEND_ERROR`, and it is the whole
 * reason the truth mode earns its cost: pretend never executes, so a migration that
 * only fails on real data or real state — a unique constraint over existing
 * duplicates, a NOT NULL column added to a populated table — passes pretend and
 * blows up in production. Shadow runs it for real and CATCHES that, reporting it as
 * a finding with the driver's own SQLSTATE and message rather than an aborted run
 * with a stack trace.
 *
 * It fires on a FAILED capture in shadow mode only; the pretend-mode counterpart
 * fires on pretend failures. Scoping by mode is what keeps the two from
 * double-reporting the same failure or mislabeling which mode it happened in — a
 * shadow failure is not a pretend failure, and the message must not say it was.
 *
 * The driver message is run through the credential redactor before it reaches the
 * finding text: a connection-level failure can carry a host, a user, or a password,
 * and a finding must never — the same discipline the agent surface will need.
 */
use Pushery\SQLens\Subjects\SubjectContext;

final readonly class MigrateErrorRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.MIGRATE_ERROR';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::for(
            self::RULE_ID,
            'sqlens.lint',
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function up(): void
                {
                    // Passes pretend (nothing runs) but fails the real migrate when the
                    // column already holds duplicates — the unique violation only exists
                    // against real data, which is exactly what shadow mode sees.
                    Schema::table('users', fn (Blueprint $table) => $table->unique('email'));
                }
                PHP,
            <<<'PHP'
                public function up(): void
                {
                    Schema::create('sessions', function (Blueprint $table): void {
                        $table->string('id')->primary();
                        $table->foreignId('user_id')->nullable();
                    });
                }
                PHP,
        );
    }

    public function appliesTo(CaptureResult $result, SubjectContext $context): bool
    {
        // The FIRST `up` only. A roundtrip's later legs have their own findings —
        // `CAP.L0.DOWN_FAILED` and `CAP.L0.DOWN_NOT_INVERTIBLE` — and the sections are
        // what keep the three apart. Without this scope a failing second `up` would be
        // reported as a broken migration when it is a broken ROLLBACK, which sends the
        // reader to fix the wrong method. A non-roundtrip run only ever has this
        // section, so nothing about it changes.
        return $result->isFail()
            && $result->mode === CaptureMode::Shadow
            && $result->section === CaptureSection::Up;
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        return Finding::fail(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The migration %s failed while being run for real against the shadow database: %s. Shadow mode runs the migration for real, so it caught a runtime error pretend could not see; fix the error the migration raises.',
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
     * The driver message the runner recorded, made safe to show: credentials
     * redacted first (a connection-level failure can carry them), then the project
     * root relativized out so the same error reads identically on every machine —
     * the determinism the whole report depends on. The fallback keeps the message
     * honest on the rare failure recorded without a detail.
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
