<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Pushery\SQLens\Tools\KnownTools;
use Pushery\SQLens\Tools\Tool;
use Pushery\SQLens\Tools\ToolVersionSupport;
use Pushery\SQLens\Tools\ToolVersionWindow;

/**
 * The Postgres Language Server as a known amplifier: its `dblint` subcommand runs a schema linter
 * over a live database and reports security findings SQLens has no rule of its own for.
 *
 * It is an amplifier and never a requirement. Nothing here installs it, the package's own checks
 * run without it, and a project that does not have it gets a named finding saying which extra
 * checks did not run — never silence.
 *
 * ## Why this one is different from Squawk, and why that matters
 *
 * Squawk reads SQL on standard input and never touches a database. `dblint` CONNECTS — with its
 * own credentials, in its own session, outside the statement and lock timeouts SQLens sets on its
 * own connection. That is the fact "primum non nocere" hangs on here, so it was measured rather
 * than assumed: with `log_statement='all'` on a probe database, a run issues sixteen statements,
 * of which zero mutate and zero lock. All catalog reads, inside one transaction, with
 * `set local search_path = ''`.
 *
 * The measurement is the reason this adapter is defensible. It is also the reason the runner
 * hands the tool a narrow configuration of its own rather than letting it run what it likes: the
 * same command with default settings also starts `typecheck` and `plpgsql_check`, which are a
 * different question about a production database than "read the catalog".
 *
 * Registered in {@see KnownTools} together with the rule map it reads, and not before: what makes
 * registration honest is being able to say what the absence COSTS, and a registration without the
 * catalog behind it would name a loss it could not size.
 */
final readonly class PglsTool implements Tool
{
    /**
     * The version whose contract was measured — the same build {@see PglsRuleMap} was read from.
     *
     * The two move together. A map measured against one build and a window admitting another is
     * exactly the state in which this adapter reads a report nobody has seen, and a report in a
     * shape nobody measured does not fail to parse — it parses into the wrong thing.
     */
    public const string MINIMUM_VERSION = '0.25.7';

    /**
     * Exclusive ceiling — the next MINOR, not the next major, and that is a deliberate narrowing.
     *
     * The usual rule (a tool may change its output at a major) assumes the tool has had a 1.0 to
     * make that promise at. This one has not: at 0.x the version number carries no compatibility
     * commitment at all, so "anything below 1.0" would admit every future release of a program
     * that is still entitled to rename its rules between minors.
     *
     * When 1.0 arrives, this bound is a decision to make again — not a number to carry forward by
     * pattern. The tool will have started promising something, and what it promises is what the
     * window should be drawn from.
     */
    public const string BELOW_VERSION = '0.26.0';

    /**
     * The exact shape of the measured `--version` line: `Version: 0.25.7`.
     *
     * Its own pattern rather than a shared one, because the tools do not agree on this line —
     * Squawk prints `squawk 2.61.0`, this one prints a label and a number with no program name in
     * it at all. Anchored at both ends, so a line this adapter does not recognize is reported as
     * unreadable rather than mined for the first number in it.
     *
     * A pre-release (`0.26.0-rc.1`) fails it, and that is the intended direction: an unreleased
     * build is precisely the one whose output nobody has measured.
     */
    private const string VERSION_LINE = '/^Version: (\d+\.\d+\.\d+)$/';

    /** The prefix every finding from this tool carries in its rule id. */
    public const string FINDING_ID_PREFIX = 'PGLS.';

    public function name(): string
    {
        return 'pgls';
    }

    /**
     * The binary is `postgrestools`, which is NOT what the project is called.
     *
     * Worth stating because the mismatch is the kind of thing a later reader corrects: the product
     * is the Postgres Language Server, the package is `@postgrestools/postgrestools`, and the
     * executable it puts on the path is `postgrestools`. Renaming this to match the product would
     * make the locator look for a file that does not exist, and the failure would read as "the
     * tool is not installed" on a machine where it is.
     */
    public function binaryName(): string
    {
        return 'postgrestools';
    }

    public function whatItEnables(): string
    {
        return 'PostgreSQL schema security checks for RLS gaps, mutable function search paths and extension placement';
    }

    /**
     * Held here rather than on the finding mapper, which is where Squawk keeps its equivalent.
     *
     * The asymmetry is deliberate and temporary in the other direction: this prefix is needed
     * BEFORE the mapper exists, because it is what keeps a missing PGLS from miscrediting Squawk's
     * suppressions the moment this tool is registered. The mapper will read it from here rather
     * than declare a second one — two constants for one prefix is how the ids and the suppression
     * bookkeeping come to disagree.
     */
    public function findingIdPrefix(): string
    {
        return self::FINDING_ID_PREFIX;
    }

    /**
     * Every platform, unlike Squawk.
     *
     * Measured from the package's own per-platform builds rather than assumed from the fact that
     * Squawk lacks one: it ships macOS, Linux (gnu and musl) and Windows binaries for both
     * architectures. So there is no platform on which this degrades for a reason nobody can fix,
     * and no constructor seam is needed to drive the other arm — there is no other arm.
     */
    public function supportsCurrentPlatform(): bool
    {
        return true;
    }

    /**
     * PostgreSQL only — it is a PostgreSQL tool, and has nothing to say about a MySQL run.
     *
     * The driver key is spelled here rather than imported from the driver: `src/Tools` is held
     * free of driver namespaces by an architecture test, and a tool declaring which engine it
     * serves must not be the seam that breaks that isolation.
     */
    public function supportsDriver(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    /**
     * How many checks are simply absent without it — the size of the measured security catalog.
     *
     * Read from the shipped map, never from the binary: asking the binary would make the answer
     * depend on whether it happens to be installed, and a machine without it would report a loss
     * of zero. That is the one direction the number must never be able to fail in.
     */
    public function uncoveredCheckCount(): int
    {
        return count(PglsRuleMap::bundled()->rules);
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
