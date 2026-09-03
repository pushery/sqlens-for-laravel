<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Privacy;

use Override;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * `log_statement` writes every statement — and its parameters — into the server log.
 *
 * ## What the value means
 *
 * PostgreSQL's `log_statement` is an enum: `none`, `ddl`, `mod`, `all`. Two of them reach data.
 *
 * `all` logs every statement, so every `SELECT … WHERE email = '…'` and every value inserted lands
 * in a text file. `mod` logs the modifying ones, which is narrower but still means every row a
 * migration or a job writes travels to the log verbatim.
 *
 * That file rarely enjoys the database's protection. It is read by operators who were never granted
 * access to the table, shipped to a log aggregator under a different retention policy, and included
 * in backups that outlive the row a deletion request removed. Nothing about it is a defect — it is
 * the setting doing exactly what it says — which is why this is reported rather than prevented.
 *
 * ## Why `mod` is a finding and `ddl` is not
 *
 * `ddl` logs schema statements. Those carry column NAMES, never row values, so they say nothing
 * about a person. The line is data, not verbosity: `ddl` on a production server is an ordinary
 * audit trail and reporting it would train people to ignore this rule.
 *
 * ## Severity, and why it is not higher
 *
 * Medium. The data is inside your own infrastructure — this is exposure to a wider circle than the
 * database grants, not exposure to the public — and the master plan puts the privacy pack's range
 * at info–medium. Medium sits below the CI gate's `high` default, so an honest finding does not
 * block a pipeline that never opted into privacy gating.
 *
 * The environment condition lives in {@see AbstractPrivacySettingRule}: the same value is how people
 * debug on a laptop, and a rule that could not tell the two apart would be muted within a week.
 */
final class StatementLoggingRule extends AbstractPrivacySettingRule
{
    public function id(): string
    {
        // `SEC.CFG.*` — a SERVER SETTING that reaches data, which is the same thing its MySQL
        // sibling `SEC.CFG.GENERAL_LOG` says about `general_log`. This id once carried a driver and
        // a fifth segment; both were wrong by the package's own contract, which knows four areas
        // and no driver segment, and `RuleIdFormat::matches()` rejected it outright.
        //
        // The CATEGORY stays `privacy` — that is deliberate and is what hangs this rule on the
        // privacy switch. Prefix and category are different axes, and the guard that governs the
        // prefix now selects on the prefix.
        return 'SEC.CFG.STATEMENT_LOGGING';
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'log_statement';
    }

    protected function privacyConcern(): string
    {
        return 'statements and their parameter values are written to the server log';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Folded and trimmed, though the server canonicalizes to lower case: the comparison costs
        // nothing and the failure it rules out — a casing mismatch reading as a safe server — is the
        // one worth ruling out.
        $value = strtolower(trim($serverValue));

        if ($value !== 'all' && $value !== 'mod') {
            return null;
        }

        return sprintf(
            'log_statement is `%s` on this production instance, so %s. %s A log file is commonly '
            .'readable by people who were never granted access to the tables, is shipped to '
            .'aggregators under their own retention, and outlives the rows an erasure request '
            .'removed. Set it to `ddl` to keep an audit trail without row values, or `none`.',
            $value,
            $this->privacyConcern(),
            $value === 'all'
                ? 'That includes reads: every `WHERE email = …` is logged with its value.'
                : 'That is every row a migration or job writes, logged verbatim.',
        );
    }
}
