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
 * `CAP.L0.DOWN_FAILED` — the roundtrip's `down` leg itself raised an error.
 *
 * This is the sibling of `CAP.L0.DOWN_NOT_INVERTIBLE`, and keeping the two apart is
 * the point of both. A `down()` that THROWS and a `down()` that runs but does not
 * restore are different defects with different fixes, and — more importantly — the
 * first makes the second unanswerable: once `down` has failed, the database holds a
 * state nobody planned, so a second `up` run against it would fail for a reason no
 * reader could attribute. The roundtrip therefore stops here, and this finding says
 * why rather than letting an unattributable failure stand in for a verdict.
 *
 * That is also why this is never reported as "down() is not invertible". Invertible
 * is a question about what `down()` LEFT BEHIND; a `down()` that did not finish left
 * behind nothing anyone can reason about. Claiming the stronger verdict would be
 * inventing evidence the run does not have.
 *
 * A `down()` that fails is worth its own finding even in isolation: it is the
 * rollback path, the one that runs when a deploy is already going wrong. Discovering
 * then that it does not work is the worst possible moment, and it is exactly what
 * this catches beforehand.
 */
use Pushery\SQLens\Subjects\SubjectContext;

final readonly class DownFailedRule implements CaptureRule
{
    public const string RULE_ID = 'CAP.L0.DOWN_FAILED';

    public function metadata(): CaptureRuleMetadata
    {
        return L0RuleMetadata::forRoundtrip(
            self::RULE_ID,
            RuleDocumentationUrl::for(self::RULE_ID),
            <<<'PHP'
                public function down(): void
                {
                    // Raises: the column was never added by this migration's up(),
                    // so the rollback path throws the moment it is needed — during a
                    // deploy that is already going wrong.
                    Schema::table('invoices', function (Blueprint $table): void {
                        $table->dropColumn('a_column_that_was_never_added');
                    });
                }
                PHP,
            <<<'PHP'
                public function down(): void
                {
                    Schema::table('invoices', function (Blueprint $table): void {
                        $table->dropColumn('reference');
                    });
                }
                PHP,
        );
    }

    public function appliesTo(CaptureResult $result, SubjectContext $context): bool
    {
        return $result->isFail()
            && $result->mode === CaptureMode::Shadow
            && $result->section === CaptureSection::Down;
    }

    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        return Finding::fail(
            self::RULE_ID,
            'sqlens.lint',
            sprintf(
                'The down() of migration %s raised an error while the roundtrip replayed it: %s. This is the rollback path, so it fails exactly when it is needed most; fix down() so it undoes what up() did. Whether down() would otherwise be a real inverse cannot be answered from this run — the roundtrip stopped here rather than judging a second up against a state the failed down left behind.',
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
