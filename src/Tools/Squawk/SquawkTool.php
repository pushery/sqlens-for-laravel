<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Tools\KnownTools;
use Pushery\SQLens\Tools\Tool;
use Pushery\SQLens\Tools\ToolVersionSupport;
use Pushery\SQLens\Tools\ToolVersionWindow;

/**
 * Squawk as a known amplifier: a PostgreSQL migration linter SQLens can run over the SQL it
 * already captured, and whose findings it maps into its own rules, levels and downtime classes.
 *
 * It is an amplifier and never a requirement. Nothing in this package installs it, the test
 * suite does not need it, and a project without it gets the full core rule set — plus a named
 * finding saying which extra checks did not run. That asymmetry is deliberate: a missing
 * amplifier must cost coverage visibly, never silently.
 *
 * Registered in {@see KnownTools} since the finding mapper landed, and not a moment before:
 * registration is what makes every PostgreSQL run on a machine without Squawk report a missing
 * tool, and while the output was not yet mapped into SQLens findings that report would have been
 * true and useless — it would have named a loss of coverage that did not exist. The adapter
 * landed first, the registration with the mapping.
 */
final readonly class SquawkTool implements Tool
{
    /**
     * The oldest version whose contract was measured — see the spike notes.
     *
     * The floor is the measured version itself rather than a guess at the oldest compatible
     * one. Every older release is software nobody here has run: its JSON may name fields
     * differently, and a mapper reading a field that moved does not fail, it reports nothing
     * and looks clean doing it.
     */
    public const string MINIMUM_VERSION = '2.61.0';

    /** Exclusive ceiling: the next major is where a tool is entitled to change its output. */
    public const string BELOW_VERSION = '3.0.0';

    /**
     * The exact shape of the measured `--version` line: `squawk 2.61.0`, nothing else.
     *
     * Anchored at both ends and demanding the program's own name, so a line this adapter does
     * not recognize is reported as unreadable instead of mined for the first number in it. A
     * pre-release (`2.62.0-rc.1`) fails it too, and that is the intended direction: an
     * unreleased build is precisely one whose output nobody has measured.
     */
    private const string VERSION_LINE = '/^squawk (\d+\.\d+\.\d+)$/';

    /**
     * @param  string  $osFamily  the platform to judge against. A parameter only so both arms of
     *                            the platform decision can be driven on one machine — production
     *                            never passes anything but the default, and a test pins that.
     */
    public function __construct(private string $osFamily = PHP_OS_FAMILY) {}

    public function name(): string
    {
        return 'squawk';
    }

    public function binaryName(): string
    {
        return 'squawk';
    }

    public function whatItEnables(): string
    {
        return 'PostgreSQL migration lint rules for locking, rewrites and unsafe column changes';
    }

    /** Delegated to the mapper that composes the ids, so the two can never disagree. */
    public function findingIdPrefix(): string
    {
        return SquawkFindingMapper::ID_PREFIX;
    }

    /**
     * Squawk links libpg_query and ships no Windows build.
     *
     * A platform reality, not a fixable install — which is why it degrades with its own named
     * reason rather than failing a strict run. A Windows CI that failed for a binary that does
     * not exist for Windows would be failing for something no one can fix.
     */
    public function supportsCurrentPlatform(): bool
    {
        return $this->osFamily !== 'Windows';
    }

    /**
     * PostgreSQL only — Squawk parses with libpg_query and has no notion of MySQL grammar.
     *
     * The driver key is spelled here rather than imported from `PgsqlDriver`: `src/Tools` is
     * held free of driver namespaces by an architecture test, and a tool declaring which engine
     * it serves must not be the seam that breaks that isolation. The cost is one literal; the
     * alternative would be an adapter that can reach into a driver's internals.
     */
    public function supportsDriver(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    /**
     * The rules SQLens has no rule of its own for — read from the shipped map.
     *
     * Deliberately NOT every rule the tool has. A rule we already cover is not a check somebody
     * loses by not installing it, and counting it would inflate the number in the one direction
     * that would make this package look better.
     */
    public function uncoveredCheckCount(): int
    {
        $uncovered = 0;

        foreach (SquawkRuleMap::bundled()->rules() as $rule) {
            if (SquawkRuleMap::bundled()->for($rule)?->parityStatus === SquawkParityStatus::MappedOnly) {
                $uncovered++;
            }
        }

        return $uncovered;
    }

    public function versionWindow(): ToolVersionWindow
    {
        return ToolVersionWindow::from(self::MINIMUM_VERSION, self::BELOW_VERSION);
    }

    public function verifyVersion(?string $rawVersionLine): ToolVersionSupport
    {
        if ($rawVersionLine === null || preg_match(self::VERSION_LINE, $rawVersionLine, $matches) !== 1) {
            return ToolVersionSupport::Unreadable;
        }

        return $this->versionWindow()->contains($matches[1])
            ? ToolVersionSupport::Supported
            : ToolVersionSupport::OutOfWindow;
    }
}
