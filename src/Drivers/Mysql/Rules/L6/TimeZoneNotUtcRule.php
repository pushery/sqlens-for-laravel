<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A MySQL server whose `time_zone` is not UTC.
 *
 * ## Why `SYSTEM` is the interesting case, not merely one wrong value among many
 *
 * MySQL ships with `time_zone = SYSTEM`, which means "whatever the host's clock is set to". The
 * database's behavior is then a property of the machine it happens to be running on: move the server
 * to a differently-configured host, or re-image the one it is on, and the same schema converts
 * timestamps differently — with nothing in the database changed and nothing failing.
 *
 * Measured on this package's own MySQL 8.4: with `time_zone = SYSTEM`,
 * `convert_tz('2026-01-01 14:00:00', 'SYSTEM', '+00:00')` returns `13:00:00`. The server silently
 * used the host's offset. It did not raise, it did not warn, and the answer is only correct if the
 * host is configured the way whoever wrote the query assumed.
 *
 * ## Why the offset form is the accepted spelling and the named one is not required
 *
 * `+00:00` works on every MySQL. The named forms — `UTC`, `Etc/UTC` — need the timezone tables
 * loaded, and a fresh install has none. Measured on the same server, with `mysql.time_zone_name`
 * empty: `convert_tz('2026-01-01 14:00:00', 'UTC', '+00:00')` returns **NULL** while the pure-offset
 * conversion returns a value. A rule that demanded the named spelling would therefore push projects
 * toward a configuration that silently produces NULL on their server.
 *
 * So all three are accepted. `GMT`, `Etc/GMT`, `Universal` and `Zulu` are deliberately not, on the
 * same argument the PostgreSQL twin makes: the same instant, a different statement of intent, and
 * the next person to touch a server set to `GMT` may well "correct" it to a local zone.
 */
final class TimeZoneNotUtcRule extends AbstractServerSettingRule
{
    /**
     * The three spellings of UTC this rule accepts.
     *
     * The offset form first because it is the one that works everywhere; the two named forms because
     * a managed host with tzdata loaded reports one of them and flagging that would be a false
     * positive on a correctly configured server.
     */
    private const array MEANS_UTC = ['+00:00', 'UTC', 'ETC/UTC'];

    public function id(): string
    {
        return 'MY.L6.TIME_ZONE_NOT_UTC';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'time_zone';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (in_array(strtoupper(trim($serverValue)), self::MEANS_UTC, true)) {
            return null;
        }

        // SYSTEM gets its own sentence. Reporting it as "not UTC" would be true and would understate
        // it: the other values at least NAME a zone, so two servers configured alike behave alike.
        // SYSTEM names nothing — it defers to the host, so the same configuration means different
        // things on different machines and changes when one of them is re-imaged.
        $problem = match (strcasecmp(trim($serverValue), 'SYSTEM') === 0) {
            true => 'the server time_zone is SYSTEM, which defers to the host\'s clock rather than naming a '
                .'zone — the database then behaves differently on a differently-configured machine, '
                .'and re-imaging the host changes it with nothing in the database touched',
            false => sprintf('the server time_zone is %s, not %s', $serverValue, $expectation->expectation ?? '+00:00'),
        };

        return sprintf(
            '%s. Every conversion that crosses the boundary — CONVERT_TZ, a TIMESTAMP read back, '.
            'NOW() compared against a stored value — then depends on that setting, and nothing fails '.
            'when it is wrong: the value is simply shifted. Prefer the offset form %s, which works on '.
            'every server; the named spellings UTC and Etc/UTC need the timezone tables loaded and '.
            'return NULL from CONVERT_TZ when they are not. %s',
            $problem,
            $expectation->expectation ?? '+00:00',
            $this->remediation($expectation),
        );
    }
}
