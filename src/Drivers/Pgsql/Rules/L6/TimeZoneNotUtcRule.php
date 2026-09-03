<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server whose `TimeZone` is not UTC.
 *
 * ## What actually goes wrong
 *
 * `TimeZone` decides how a `timestamptz` is rendered on the way out and how a bare timestamp literal
 * is interpreted on the way in. Set it to `Europe/Vienna` and `now()` still stores the same instant —
 * this is not data corruption — but every value a client reads back arrives shifted, and any
 * expression that crosses the type boundary (`::date`, `date_trunc`, a `DEFAULT now()::date`) lands
 * on a different day for two hours of every day, and a different day for one hour more in summer.
 *
 * The bugs that follow are the worst kind: seasonal, off-by-one, and reproducible only during the
 * hours nobody is looking. A daily aggregate is short one day and long the next; a "today" filter
 * silently excludes the first two hours of the day. Which is why this is worth a rule at all — the
 * failure is not loud, it is quiet and periodic.
 *
 * ## Why it reads the server's value and not the session's
 *
 * `TimeZone` is settable per session, and things do set it: `PGTZ`, a per-role `ALTER ROLE … SET`,
 * a connection library, or SQLens' own reading session. A rule looking at what the audit connection
 * is running with would report the audit's own environment as the server's configuration — and would
 * do it confidently, on a correctly configured server. The base hands this rule only the server's
 * value for exactly that reason, and the false-positive counter-probe is what holds the line.
 */
final class TimeZoneNotUtcRule extends AbstractServerSettingRule
{
    /**
     * The two spellings that mean UTC and are worth accepting.
     *
     * PostgreSQL resolves plenty of other names to a zero offset — `Etc/GMT`, `Zulu`, `Universal`,
     * `GMT` — and they are deliberately NOT here. They are the same instant but a different
     * statement: a server set to `GMT` was configured by somebody who did not mean UTC, and the next
     * person to touch it may well "correct" it to a local zone. The rule is about the configuration
     * being unambiguous, not merely about the offset being zero today.
     */
    private const array MEANS_UTC = ['UTC', 'Etc/UTC'];

    public function id(): string
    {
        return 'PG.L6.TIMEZONE_NOT_UTC';
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
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'TimeZone';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (in_array($serverValue, self::MEANS_UTC, true)) {
            return null;
        }

        // `localtime` is its own sentence. It does not name a zone at all — it tells the server to
        // take whatever the host's clock is configured to, which means the database's behavior
        // changes when somebody re-images the machine, and two nodes of the same cluster can disagree.
        // Reporting that as "not UTC" would be true and would badly understate it.
        $problem = in_array($serverValue, ['localtime', 'SYSTEM'], true)
            ? sprintf(
                'the server TimeZone is %s, which follows the host\'s clock rather than naming a zone — '.
                'two machines running the same database can then disagree, and re-imaging one changes its behavior',
                $serverValue,
            )
            : sprintf('the server TimeZone is %s, not %s', $serverValue, $expectation->expectation ?? 'UTC');

        return sprintf(
            '%s. Timestamps still store the correct instant, but every boundary expression — a cast to date, '.
            'a date_trunc, a "today" filter — lands on the wrong day for part of each day, and the offset moves '.
            'with daylight saving. %s',
            $problem,
            $this->remediation($expectation),
        );
    }
}
