<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * `secure_file_priv` is empty — the `FILE` privilege reaches the whole host.
 *
 * This is the other half of {@see FileGrantRule}, and the two are deliberately separate findings. That
 * one reports an ACCOUNT holding a privilege; this reports the SERVER setting deciding how far that
 * privilege reaches. Reporting them as one would be a single alarm for two facts that are fixed in
 * different places by different people — and either one alone is already worth acting on.
 *
 * ## Why the empty value is the finding and `NULL` is not
 *
 * MySQL writes the switched-off state as the four-character string `NULL`, and the unrestricted
 * state as the empty string. The naive reading of those is exactly INVERTED: `''` looks like nothing
 * is configured, and it is the state in which `LOAD_FILE()` reads any file the server's
 * operating-system user can read and `SELECT … INTO OUTFILE` writes one anywhere it can write.
 * {@see SecureFilePrivState} carries that classification, with the measurement behind it.
 *
 * A directory is a deliberate limit and passes. Switched off passes. Only the empty value is the
 * finding, which is why this rule is quiet on every server somebody has actually configured.
 *
 * ## Why `high` rather than `critical`
 *
 * On its own the setting grants nobody anything: without an account holding `FILE`, an unrestricted
 * `secure_file_priv` changes nothing. It is the multiplier on a privilege rather than a privilege,
 * and reporting it at the top of the axis would put it beside findings that need nothing else to be
 * true.
 */
final class SecureFilePrivRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.SECURE_FILE_PRIV';
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
        return 'secure_file_priv';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // The classifier, not a comparison against the expectation string. The matrix holds the
        // value a hardened server has, but "is it the expected value" cannot express this variable:
        // a PATH is neither the expectation nor a finding, and a straight string comparison would
        // report every deliberately confined server as wrong.
        $state = SecureFilePrivState::forServerValue($serverValue);

        if (! $state->isUnrestricted()) {
            return null;
        }

        return sprintf(
            'secure_file_priv is %s, so MySQL places NO limit on where the FILE privilege may read '
            .'and write: LOAD_FILE() reads any file the server process can read, and '
            .'SELECT … INTO OUTFILE writes one anywhere it can write — as the server\'s '
            .'operating-system user, not as the account connecting. On its own this grants nobody '
            .'anything; combined with an account that holds FILE it is the difference between a '
            .'database problem and a host problem. Note that the empty value is the DANGEROUS one '
            .'here: MySQL writes the switched-off state as the string NULL, so a server that looks '
            .'unconfigured is the one with no limit at all. %s',
            $state->describe(),
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
            'reads the RUNNING value, not the file: a setting changed on disk and not yet reloaded is invisible here, and one changed only for this session would be read as the server\'s',
            'reads the directory the setting names, never its contents or its permissions. A restricted path that anyone can write to is as reachable as an unrestricted one, and that is a filesystem fact outside this run',
        ];
    }
}
