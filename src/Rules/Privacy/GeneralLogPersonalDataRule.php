<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Privacy;

use Override;
use Pushery\SQLens\Rules\Security\GeneralLogRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * MySQL's general query log is on, and every row value in every statement is now in a file.
 *
 * ## Why this exists beside {@see GeneralLogRule}, which reads the SAME variable
 *
 * They ask different questions about one setting, and a project usually cares about exactly one of
 * them. The hardening view is about SECRETS — `CREATE USER … IDENTIFIED BY` writes the password into
 * the log, and a credential in a log stays valid until somebody rotates it. This one is about
 * PERSONAL DATA: every `WHERE email = …`, every `INSERT` of a name or an address, written verbatim
 * into a file that outlives the row.
 *
 * That difference is not cosmetic, because the two are gated differently and by different people. A
 * team hardening a server filters on `--category=security` and never sees a privacy finding; a team
 * answering a data-protection question filters on `--category=privacy` and never sees a security
 * one. One rule can carry only one category, so a single rule here would be invisible to whichever
 * half did not pick it — and a report missing a category looks exactly like a clean report.
 *
 * The cost is that both fire on the same server value. That is what `suppressed_by` is for: the second view is
 * recorded against the first rather than printed twice.
 *
 * ## The environment condition, and why it is not optional
 *
 * Inherited from {@see AbstractPrivacySettingRule}: this only reports on production. The general log
 * is exactly how people debug on a laptop, and a rule that could not tell the two apart would be
 * muted within a week — taking the production case with it. Where the run cannot establish which it
 * is looking at, the answer is `undetermined` with the reason named, never a quiet pass.
 */
final class GeneralLogPersonalDataRule extends AbstractPrivacySettingRule
{
    /**
     * The id carries the CONCERN, not the category, and the suffix is what keeps it honest.
     *
     * `SEC.CFG.*` is the prefix for a server setting that reaches data — the same one its sibling
     * uses, because they describe the same setting. The category is a separate axis and is what
     * hangs this rule on the privacy switch.
     *
     * The sibling keeps the bare `SEC.CFG.GENERAL_LOG` although this one is arguably the better
     * claim to it. Renaming a shipped rule id is a breaking change: it appears in committed
     * baselines, in `#[SqlensIgnore(rules: […])]` annotations and in a documentation URL, and a
     * suppression that names a rule which no longer exists silently suppresses nothing.
     */
    public function id(): string
    {
        return 'SEC.CFG.GENERAL_LOG_PERSONAL_DATA';
    }

    /**
     * Medium, matching its PostgreSQL counterpart rather than the hardening view's High.
     *
     * Deliberate: Medium sits below the CI gate's `high` default, so an honest privacy finding does
     * not break a pipeline that never opted into privacy gating. A project that wants it blocking
     * lowers `security.min_severity`, which is a choice it makes rather than one made for it.
     */
    #[Override]
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'general_log';
    }

    protected function privacyConcern(): string
    {
        return 'every statement and every value in it is written to the general query log';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // MySQL reports this variable as `ON`/`OFF` through SHOW VARIABLES and as `1`/`0` through
        // the performance schema. Both spellings mean the same thing and both reach this rule
        // depending on the reader, so both are matched — a rule that knew only one would be silent
        // on half the servers and there would be nothing to see.
        $value = strtoupper(trim($serverValue));

        if ($value !== 'ON' && $value !== '1') {
            return null;
        }

        return sprintf(
            'general_log is %s on this production instance, so %s — every `WHERE email = …` with '
            .'its value, every name and address an INSERT carries, every parameter of every job. '
            .'The log does not redact, because it is a debugging tool: it records what was sent. '
            .'The file is commonly readable by people who were never granted access to the tables, '
            .'is swept into log shipping under its own retention, and OUTLIVES THE ROWS AN ERASURE '
            .'REQUEST REMOVED — which is the part that turns a debugging convenience into a '
            .'compliance problem. This is off by default and meant to be on for minutes, not for an '
            .'uptime. %s',
            $serverValue,
            $this->privacyConcern(),
            $this->remediation($expectation),
        );
    }
}
