<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Privacy\StatementLoggingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * PostgreSQL is logging every statement, so the credentials inside them are in a file.
 *
 * ## The half of the pair that was missing, and how the gap came about
 *
 * MySQL's `general_log` had a hardening view ({@see GeneralLogRule}) and PostgreSQL's `log_statement`
 * had a privacy view ({@see StatementLoggingRule}). Same concern, opposite categories, one per
 * engine — measured by instantiating both rather than by reading them. Nobody decided that; it is
 * what two tickets written months apart produced, and each docblock argued its own choice
 * convincingly, which is exactly why it survived.
 *
 * The consequence was invisible in the way this package cares about. A team hardening a PostgreSQL
 * server filters on `--category=security`, and `log_statement = all` never reached them — although
 * `CREATE ROLE app LOGIN PASSWORD 'hunter2'` goes into that log with the password, the same as it
 * does on MySQL. Nothing was red. The report simply did not contain a finding, which reads as a
 * clean server.
 *
 * ## Why a second rule rather than a second category on the first
 *
 * `category()` returns ONE category, and widening it to a list would touch every category filter,
 * every reporter, the SARIF mapping and the gate — a change to a core axis for two settings. The
 * two-rule shape costs a duplicate finding on the same value instead, and that has an answer:
 * `suppressed_by` records the second view against the first rather than printing it twice.
 *
 * ## No environment condition here, deliberately
 *
 * Its privacy sibling only reports in production, because a laptop logging its own queries is how
 * people debug. This one does not inherit that, and the difference is the subject: a password in a
 * log is a leaked credential wherever the log is. A development database that shares a password
 * with anything else has already lost it, and "it was only staging" is the sentence that follows
 * every credential incident.
 */
final class StatementLoggingSecretsRule extends AbstractSettingSecurityRule
{
    /**
     * The suffix marks the CONCERN, and the bare id stays with the sibling that shipped first.
     *
     * Renaming a shipped rule id is a breaking change — it appears in committed baselines, in
     * `#[SqlensIgnore(rules: […])]` annotations and in a documentation URL, and a suppression naming
     * a rule that no longer exists suppresses nothing while looking like it does.
     */
    public function id(): string
    {
        return 'SEC.CFG.STATEMENT_LOGGING_SECRETS';
    }

    /** Level 0 like the rest of the suite: gated by `security.min_severity`, never by strictness. */
    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * High, matching the MySQL hardening view rather than the privacy one's Medium.
     *
     * The two severities on one setting are not an inconsistency: they measure different damage. A
     * credential in a log stays valid until somebody rotates it, and nobody rotates what they do not
     * know leaked — that is High. Personal data in a log is a retention and erasure problem, serious
     * and slower, which its sibling reports at Medium.
     */
    #[Override]
    public function severity(): Severity
    {
        return Severity::High;
    }

    /**
     * This rule supplies the fact the MATRIX could not, so the matrix's abstention does not silence it.
     *
     * Without this the rule was DEAD — measured, not feared: `judgeSchemaObject()` returns an empty
     * array for every input when the expectation is unjudged and the rule does not say it brings its
     * own. `log_statement` is exactly such an entry, and deliberately so: the matrix cannot answer
     * from the value alone, because `all` is a problem on a production server and how people debug on
     * a laptop. A matrix entry claiming either would be wrong half the time.
     *
     * The missing fact this rule supplies is not the environment — it is the SUBJECT. A password in
     * a log is a leaked credential wherever the log is, and a development database that shares a
     * password with anything else has already lost it. That is a judgment from the value, which is
     * precisely what the matrix said it could not make on its own.
     *
     * Its privacy sibling reaches the same place through {@see AbstractPrivacySettingRule}, which
     * declares this for the whole family; the security family does not, because most of its settings
     * ARE judged by the matrix — `general_log` is, measured.
     */
    #[Override]
    protected function bringsOwnExpectation(): bool
    {
        return true;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'log_statement';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // `all` and `mod` are the two of the four values that reach data. `ddl` logs schema changes
        // only and `none` logs nothing, and neither carries a value — so neither is this rule's
        // subject, and reporting them would make the rule noise on the setting people are told to
        // use.
        $value = strtolower(trim($serverValue));

        if ($value !== 'all' && $value !== 'mod') {
            return null;
        }

        // An if, not a ternary, and that is a MEASUREMENT rather than a style preference.
        //
        // pcov reports the continuation lines of a multi-line ternary arm as UNCOVERED even when the
        // arm demonstrably runs: with this written as `$x = cond ? 'a'.'b' : ''`, the empty arm was
        // counted and the two-line arm was not, while a probe proved `all` produces the sentence and
        // `mod` does not. The 100% floor then fails over FORMATTING, and the next reader goes looking
        // for a missing test that does not exist. Both arms are ordinary statements now.
        $everyRead = '';

        if ($value === 'all') {
            $everyRead = ' At `all` that includes every read, so a token compared in a WHERE clause '
                .'is logged as well as one that was written.';
        }

        return sprintf(
            'log_statement is `%s`, so statements are being written to the server log VERBATIM — '
            .'including the ones nobody would log on purpose. `CREATE ROLE app LOGIN PASSWORD …` '
            .'goes in with the password; so does an UPDATE that sets a token, and any value '
            .'interpolated into SQL rather than bound.%s The log does not redact, because it is a '
            .'debugging tool: it records what was sent. The result is a file — usually outside '
            .'whatever protects the database itself, and routinely swept into log shipping — '
            .'holding a copy of what the database was guarding. Credentials in it stay valid until '
            .'somebody rotates them, and nobody rotates what they do not know leaked. Set it to '
            .'`ddl` to keep an audit trail without values, or `none`. %s',
            $value,
            $everyRead,
            $this->remediation($expectation),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the RUNNING value, not the file: a setting changed in postgresql.conf and not yet '
            .'reloaded is invisible here, and one changed only for this session would be read as the '
            .'server\'s',
            'cannot see where the log GOES. Statements written to a file only root can read are a '
            .'different exposure from ones shipped to an aggregator a whole team queries, and the '
            .'destination — not this switch — decides how far a credential travels',
            'says nothing about what is IN the statements. A project that binds every value still '
            .'writes those values to this log, because the server logs the statement it executed, '
            .'not the one the application wrote',
            'judges only `log_statement`. PostgreSQL can put statement text into a log through other '
            .'settings — `log_min_duration_statement` logs slow queries in full, and the auto_explain '
            .'module logs them with their parameters — and neither is read here, so a quiet verdict '
            .'from this rule is not a statement about the server\'s logging as a whole',
        ];
    }
}
