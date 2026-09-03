<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * `local_infile` is on — the server may ask the CLIENT for a file.
 *
 * The direction is what makes this worth reporting, and it is the opposite of what the name suggests.
 * `LOAD DATA LOCAL INFILE` does not read a file on the server: the server sends the client a request
 * naming a path, and a compliant client reads that file off its own disk and uploads it. The client
 * decides nothing about which path — it is told.
 *
 * So a server that is compromised, or one an application was pointed at by mistake, can ask for
 * `/etc/passwd`, an `.env`, or a key file, and a client with the capability enabled hands it over.
 * The application need not run a single `LOAD DATA` statement of its own for this to happen; the
 * request comes from the other end of the connection.
 *
 * ## Why `medium`
 *
 * It needs a hostile or hijacked server to be exploited, which is a bigger precondition than most
 * findings in this suite carry. What it does not need is any privilege on the account: the capability
 * is negotiated at connection time, not granted.
 *
 * ## The honesty limit
 *
 * This reads the SERVER's side of the negotiation. A client can refuse independently — PHP's
 * `mysqli.allow_local_infile` and PDO's `PDO::MYSQL_ATTR_LOCAL_INFILE` both default to off on
 * current builds — and this rule cannot see that. It reports that the server would ask, not that
 * anybody would answer.
 */
final class LocalInfileRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.LOCAL_INFILE';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

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
        return 'local_infile';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Case-folded and trimmed: MySQL answers `ON`/`OFF` here, but the value travels through a
        // config file that accepts `1`/`0` and `on`/`off`, and flagging a spelling would be a pure
        // false positive. `1` is the same state as `ON` and is treated as one.
        $value = strtoupper(trim($serverValue));

        if ($value !== 'ON' && $value !== '1') {
            return null;
        }

        return sprintf(
            'local_infile is %s, so this server may ask the CLIENT to send it a file — and the '
            .'direction is the opposite of what the name suggests. LOAD DATA LOCAL INFILE does not '
            .'read a file on the server: the server sends the client a request naming a path, and a '
            .'compliant client reads that path off its OWN disk and uploads it. The client does not '
            .'choose the path, it is told one. A compromised server, or one an application was '
            .'pointed at by mistake, can therefore ask for an .env or a key file without the '
            .'application running any LOAD DATA statement of its own. No privilege on the account is '
            .'involved: the capability is negotiated at connection time, not granted. This reads the '
            .'SERVER\'s side only — a client can refuse independently, and current PHP builds do by '
            .'default, which this rule cannot see. %s',
            $serverValue,
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
            'judges the server\'s willingness, not any client\'s use of it. `local_infile` on with no client that asks for it exposes nothing today; it is the client somebody adds later that this exists to get ahead of',
        ];
    }
}
