<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The server still negotiates a TLS version that has been withdrawn.
 *
 * TLS is on, the connection reports as encrypted, and a monitoring dashboard says so — which is what
 * makes this different from {@see TlsDisabledRule} sitting beside it. There, nothing is encrypted and
 * that is at least visible. Here everything looks right, and the exposure is that an active attacker
 * gets a version to negotiate DOWN to. TLS 1.0 and 1.1 are withdrawn (RFC 8996); their weaknesses are
 * reachable exactly when both ends will still agree to them.
 *
 * ## The value is almost never wrong by accident
 *
 * PostgreSQL has shipped `TLSv1.2` as the default since the parameter existed, so a server below it
 * was moved there deliberately — usually years ago, for one client that no longer connects. That is
 * the shape of the finding: not a bad default nobody fixed, but an exception nobody removed. It is
 * also why the remediation is a reload rather than a migration plan.
 *
 * ## Why `high` and not `critical`
 *
 * Reaching the weakness needs an attacker on the path between client and server, which is a
 * precondition and not a given. `critical` is reserved here for findings that need nothing else to
 * be true. It sits at the same severity as its disabled-TLS neighbor on purpose: one says the door
 * is open, the other says the lock is from 2006, and neither is worth ranking above the other
 * without knowing the network.
 *
 * ## The comparison is ordered, never lexical
 *
 * `'TLSv1.10' < 'TLSv1.2'` in every string comparison there is. A rule that compared names would
 * report a server that is STRICTER than required and tell somebody to weaken it — see
 * {@see TlsProtocolVersion} for why the ordering is a list and why an unplaceable name is
 * `undetermined` rather than a guess.
 */
final class TlsMinVersionRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.TLS_MIN_VERSION';
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
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'ssl_min_protocol_version';
    }

    /**
     * @return list<string>
     */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [SettingCrossFacts::TLS_OFFERED];
    }

    /**
     * Settled before the value means anything: an unplaceable version name.
     *
     * It cannot go in {@see self::violation()}, which may only answer "fine" or "wrong" — and a name
     * this package has never measured is neither. Reporting it as fine would be the silent green;
     * reporting it as a violation would be a claim about an ordering nobody established.
     *
     * The TLS-is-off case is deliberately NOT here. It is a reasoned pass rather than a
     * precondition, because the value was read and judged and found unable to cause harm — see
     * {@see self::reasonedPass()}.
     */
    #[Override]
    protected function precondition(SchemaObject $object): ?RuleVerdict
    {
        $value = $object->getString('server_value');

        if ($value === null || TlsProtocolVersion::rank($value) !== null) {
            return null;
        }

        return RuleVerdict::undetermined(
            sprintf(
                'ssl_min_protocol_version reads %s, which is not a TLS version name this package has '
                .'measured, so it could not be placed against the %s floor. The comparison is by '
                .'ORDER rather than by name — a string comparison would rank a name like TLSv1.10 '
                .'below TLSv1.2 — and a name with no known position has no order to compare.',
                $value,
                TlsProtocolVersion::ORDER[2],
            ),
            UndeterminedReason::UnsupportedEngine,
        );
    }

    /**
     * TLS is not offered at all, so the minimum describes a capability that is not running.
     *
     * A pass with a sentence rather than silence, and rather than a second alarm. `ssl = off` already
     * has its own finding at the same severity; adding this one beside it would report one fact
     * twice, and a report that says the same thing twice is one people stop reading. The sentence
     * names the other finding so the pass cannot be mistaken for "this part is fine".
     *
     * Measured, not assumed: on PostgreSQL 18.4 with `ssl = off`, `ssl_min_protocol_version` still
     * reads its configured value. The judged value therefore gives no hint that TLS is off, which is
     * exactly why the fact has to be measured beside it.
     */
    #[Override]
    protected function reasonedPass(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Only ever a replacement for a finding that would otherwise be MADE. Without this rung the
        // hook fires on every value the moment TLS is off, and the sentence below then asserts the
        // value is under the floor about a server sitting exactly on it — a pass with a false
        // sentence, which is worse than the double finding it was written to prevent.
        //
        // Found by the end-to-end audit against a live server rather than by the unit arms: the
        // development instance runs `ssl = off` with the default `TLSv1.2`, which is precisely the
        // combination the hooks are wrong about and the one nobody thinks to write a case for.
        if (TlsProtocolVersion::isBelow($serverValue, (string) $expectation->expectation) !== true) {
            return null;
        }

        $ssl = strtolower(trim((string) $this->crossFact($object, SettingCrossFacts::TLS_OFFERED)));

        if (in_array($ssl, ['on', 'true', '1', 'yes'], true)) {
            return null;
        }

        return sprintf(
            'ssl_min_protocol_version is %s, which is below the %s floor — but ssl is %s, so this '
            .'server negotiates no TLS at all and the minimum describes a capability that is not '
            .'running. Reported once, by SEC.CFG.TLS_DISABLED, rather than twice: raising both would '
            .'put two findings on one fact, and the minimum becomes worth acting on the moment TLS '
            .'is switched on.',
            $serverValue,
            TlsProtocolVersion::ORDER[2],
            $ssl === '' ? 'not on' : $ssl,
        );
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $floor = (string) $expectation->expectation;

        // Null is unreachable here: an unplaceable server value was settled in `precondition()`, and
        // the floor comes from the shipped matrix, whose entry a consistency test holds to a name in
        // TlsProtocolVersion::ORDER. Written as an explicit comparison anyway rather than a `?? false`
        // so a future matrix edit fails loudly at the test rather than quietly here.
        if (TlsProtocolVersion::isBelow($serverValue, $floor) !== true) {
            return null;
        }

        return sprintf(
            'ssl_min_protocol_version is %s, so this server will still negotiate TLS versions below '
            .'%s. TLS 1.0 and 1.1 are withdrawn (RFC 8996) and their weaknesses are reachable exactly '
            .'when both ends still agree to them — which makes this harder to notice than TLS being '
            .'off: every connection reports as encrypted and a dashboard says so, while an attacker '
            .'on the path has a version to negotiate down to. The default has been %s for as long as '
            .'the parameter has existed, so a server below it was moved there deliberately, usually '
            .'for one client that no longer connects. %s',
            $serverValue,
            $floor,
            $floor,
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
            'says what the server will ACCEPT, not what anybody negotiates. A deployment whose clients all insist on TLS 1.3 is never exposed to the older version this reports, and nothing about the clients is visible from the catalog',
            // Sharpened rather than dropped: the run CAN establish that something sits in front of
            // the server — the pooler reading is a measured three-state verdict, and it is a fact on
            // the very subject this rule judges. What no reading reaches is that proxy\'s own TLS
            // policy. Saying "the topology is invisible" claimed a blindness the package does not
            // have, and a limitation that overstates itself is discounted along with the accurate ones.
            'cannot read the TLS policy of anything standing in front of the server. Whether a pooler is in the path is established and reported beside this finding; what it negotiates with a client is not, so a proxy that terminates or re-negotiates TLS may put this parameter out of reach while the parameter reads the same either way',
        ];
    }
}
