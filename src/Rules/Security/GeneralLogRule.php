<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Contracts\SettingCrossFactCollector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Settings\JudgesProductionOnly;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The general query log is on — every statement is being written down, verbatim.
 *
 * Including the ones nobody would put in a log on purpose. `CREATE USER … IDENTIFIED BY 'secret'`
 * goes in with the password. So does an `UPDATE` that sets a token, and any value interpolated into
 * SQL rather than bound. The log does not redact, because it is a debugging tool: it records what
 * was sent.
 *
 * That turns a file — often world-readable, usually outside whatever protects the database itself,
 * and routinely swept into log shipping — into a copy of the data the database was guarding. The
 * credentials in it stay valid until somebody rotates them, and nobody rotates what they do not know
 * leaked.
 *
 * ## Why this is a finding rather than a preference
 *
 * It is off by default, and it is meant to be switched on for a few minutes while somebody is
 * looking at something. A server that has it on is almost always one where that was forgotten — the
 * cost is silent and grows with uptime, which is exactly the shape a person does not notice.
 *
 * ## The honesty limit
 *
 * This reports that statements are being recorded, and — since the destination became a cross-fact —
 * WHERE they are written, quoted from the server's own `log_output`. What it still cannot tell is who
 * can read that destination or whether anything ships it anywhere: those are questions about the
 * host, not about the server's catalog, and a rule claiming them would be claiming more than it read.
 *
 * The path is deliberately absent even though `general_log_file` holds it. A path names a directory
 * layout, and a finding travels into a JSON report, a SARIF file and a CI annotation.
 */
final class GeneralLogRule extends AbstractSettingSecurityRule
{
    use JudgesProductionOnly;

    /**
     * The environment, optional for the same reason its privacy sibling makes it optional.
     *
     * Absent, the precondition answers `undetermined` with its reason rather than judging — which
     * is the safe direction and the one the three-valued design is for. A rule that treated an
     * absent service as "not production" would report a pass about a server nobody placed.
     */
    public function __construct(
        string $projectRoot,
        private readonly ?RunEnvironment $environment = null,
    ) {
        parent::__construct($projectRoot);
    }

    /**
     * Judged on production only — and this is a SECURITY rule saying so, which deserves its reason.
     *
     * The general query log is how people debug on a laptop. A rule that could not tell a laptop
     * from a production server would be muted within a week, taking the production case with it —
     * the same argument its privacy sibling already makes about the same setting, and the two
     * describing one server value must not disagree about when it matters.
     *
     * What makes this safe on a SECURITY rule is the third value. Only a project declaring, in its
     * own `app.env`, that this is not production quiets it; an environment nothing places is a
     * FINDING. So the failure mode people fear here — a security check silent against production on
     * the default path — cannot happen: silence has to be asked for.
     *
     * Note what does NOT gate it: the audit's `--profile` flag. That is a label the caller picks per
     * invocation, and letting it withhold a security finding is the shape this package refuses
     * everywhere else. `app.env` is the application's own statement about itself.
     */
    #[Override]
    protected function precondition(SchemaObject $object): ?RuleVerdict
    {
        return $this->productionPrecondition($object, $this->environment);
    }

    /** @return string what this rule would report on production — for the not-production sentence */
    #[Override]
    protected function environmentConcern(): string
    {
        return 'every statement reaching this server is written down verbatim, credentials included';
    }

    public function id(): string
    {
        return 'SEC.CFG.GENERAL_LOG';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::High;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'general_log';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $value = strtoupper(trim($serverValue));

        if ($value !== 'ON' && $value !== '1') {
            return null;
        }

        return sprintf(
            'general_log is %s, so every statement this server receives is being written down '
            .'VERBATIM — including the ones nobody would log on purpose. CREATE USER … IDENTIFIED BY '
            .'goes in with the password; so does an UPDATE that sets a token, and any value '
            .'interpolated into SQL rather than bound. The log does not redact, because it is a '
            .'debugging tool: it records what was sent. The result is a file — often world-readable, '
            .'usually outside whatever protects the database itself, and routinely swept into log '
            .'shipping — holding a copy of what the database was guarding. Credentials in it stay '
            .'valid until somebody rotates them, and nobody rotates what they do not know leaked. '
            .'This is off by default and meant to be on for minutes, not for an uptime. This reports '
            .'that statements are being recorded; %s %s',
            $serverValue,
            $this->destinationSentence($object),
            $this->remediation($expectation),
        );
    }

    /**
     * What the server says about the destination, or an honest sentence when it would not say.
     *
     * ## Read, but NOT required — and the difference decides whether this rule can be silenced
     *
     * A required cross-fact makes the whole judgment `undetermined` when the fact is missing. That
     * is right for a fact the verdict TURNS on, and wrong here: `general_log = ON` is a finding on
     * its own, and the destination only says how far the statements travel. Declaring it required
     * would mean a server that refuses `@@global.log_output` gets no finding about a general log
     * that is demonstrably running — a refusal on one variable silencing the answer about another.
     *
     * So the absence lands in the SENTENCE instead, which is the same three-valued honesty one
     * level down: the finding still fires, and it says which half could not be established.
     *
     * Quoted verbatim rather than mapped: `log_output` is a SET, so `FILE`, `TABLE`, `FILE,TABLE`
     * and `NONE` are all things it really answers, and inventing a vocabulary here would put words
     * in MySQL's mouth. What stays out of the finding either way is the PATH — `general_log_file`
     * names a directory layout, and a report is not the place to publish one.
     */
    private function destinationSentence(SchemaObject $object): string
    {
        $output = trim((string) $this->crossFact($object, SettingCrossFactCollector::GENERAL_LOG_OUTPUT));

        if ($output === '') {
            return 'where they go could not be read, so how far they travel is not established here '
                .'— and who can read them is a question about the host either way, which this does '
                .'not read and does not claim.';
        }

        return sprintf(
            'they are written to %s (`log_output`). A TABLE is readable by whoever holds SELECT on '
            .'it; a FILE usually sits outside whatever protects the database and is routinely swept '
            .'into log shipping. WHO can read either is a question about the host, which this does '
            .'not read and does not claim. The path is deliberately not repeated here.',
            $output,
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the RUNNING value, not the file: a setting changed on disk and not yet reloaded is invisible here, and one changed only for this session would be read as the server\'s',
            'reads the DESTINATION (`log_output`) but not what happens to it. A file that ships to an aggregator and one that never leaves the host are the same `FILE` here, and who may read the `mysql.general_log` table is a grant question this rule does not ask',
            'says nothing about what is IN the statements. A project whose queries are fully parameterized still writes the parameters to this log, which is the part people are surprised by',
        ];
    }
}
