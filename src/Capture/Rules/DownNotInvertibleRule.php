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
 * `CAP.L0.DOWN_NOT_INVERTIBLE` — the roundtrip's SECOND `up` failed, which proves
 * `down()` did not restore the schema it was given.
 *
 * This is a verdict no tool that only reads `.sql` can reach. Whether `down()` is a
 * real inverse is not a property of its text: it is a property of the state it
 * leaves behind, and the only way to learn it is to undo and redo against a database
 * somebody is allowed to break. The roundtrip does exactly that, and this rule is
 * what turns its outcome into an answer.
 *
 * The section is the whole distinction. THREE different things can go wrong in a
 * roundtrip and they are never conflated:
 *
 *   - `up` fails      → `CAP.L0.MIGRATE_ERROR`: the migration itself is broken, and
 *                       `down()` was never even reached.
 *   - `down` fails    → `CAP.L0.DOWN_FAILED`: the reverse leg raised an error. What
 *                       `down()` would have left behind is unknown, so nothing can
 *                       be said about invertibility.
 *   - `up again` fails → THIS rule: both legs ran, and the schema `down()` left is
 *                       one the migration cannot be applied to a second time.
 *
 * Reading the third as the first would tell a user their migration is broken when it
 * is their rollback that is; reading it as the second would blame an error that
 * never happened. Each case gets its own id, its own message and its own page.
 *
 * The false positive worth naming is the DELIBERATELY irreversible migration — a
 * data migration whose `down()` cannot restore what it consumed is a legitimate
 * design, not a defect. That case is silenced with a suppression annotation on the
 * migration class, which is a decision recorded in the code rather than a rule
 * weakened for everyone.
 */
use Pushery\SQLens\Subjects\SubjectContext;

final readonly class DownNotInvertibleRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.DOWN_NOT_INVERTIBLE';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::forRoundtrip(
            self::RULE_ID,
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function up(): void
                {
                    Schema::create('invoices', function (Blueprint $table): void {
                        $table->id();
                    });
                }

                public function down(): void
                {
                    // Not an inverse: the table survives, so applying `up` a second
                    // time fails on a table that already exists. Nothing about this
                    // is visible in the SQL — only the replay finds it.
                    Schema::dropIfExists('invoice_lines');
                }
                PHP,
            <<<'PHP'
                public function up(): void
                {
                    Schema::create('invoices', function (Blueprint $table): void {
                        $table->id();
                    });
                }

                public function down(): void
                {
                    Schema::dropIfExists('invoices');
                }
                PHP,
        );
    }

    public function appliesTo(CaptureResult $result, SubjectContext $context): bool
    {
        return $result->isFail()
            && $result->mode === CaptureMode::Shadow
            && $result->section === CaptureSection::UpAgain;
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        return Finding::fail(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The migration %s could not be applied again after its own down() ran, so down() is not a real inverse: %s. The roundtrip replayed up, then down, then up in a throwaway database, and the second up failed against the schema down() left behind — make down() restore exactly what up() changed, or annotate the migration as deliberately irreversible.',
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
     * The driver message, made safe and deterministic: credentials redacted first,
     * then the project root relativized out so the same failure reads identically on
     * every machine.
     */
    private function detail(CaptureResult $result, string $projectRoot): string
    {
        $detail = (new CredentialRedactor)->redact($result->failureDetail ?? 'the capture recorded no further detail');

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

        return str_replace(rtrim($projectRoot, '/').'/', '', $detail);
    }
}
