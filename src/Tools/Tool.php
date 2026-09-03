<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * A known external tool SQLens can lean on — Squawk, pgFormatter, SQLFluff, the
 * Postgres Language Server, plpgsql_check. Every one is an optional amplifier, never
 * a requirement: the core rules run without it. This contract is what a strict CI
 * needs to turn "amplifier not installed" from a silent loss of coverage into a named
 * result.
 *
 * The concrete tools (the Squawk adapter first) land with the rule packs; the
 * production registry is empty until then. This contract and the locator are ready
 * ahead of them because they depend only on the finding core, and drawing the edge
 * honestly beats a second implementation later.
 */
interface Tool
{
    /** The stable identifier used in config, the header, and finding text (e.g. "squawk"). */
    public function name(): string;

    /** The executable to look for on the configured path or `$PATH` (e.g. "squawk"). */
    public function binaryName(): string;

    /**
     * A one-line English statement of what this tool adds — the "what it would have
     * brought" a non-strict run reports when the tool is missing, so the loss of
     * coverage is visible and actionable rather than silent.
     */
    public function whatItEnables(): string;

    /**
     * Whether this tool has a build for the current platform. Squawk has no Windows
     * build (libpg_query), so on Windows it degrades with a named reason while the
     * platform-neutral core rules keep running.
     */
    public function supportsCurrentPlatform(): bool;

    /**
     * Whether this tool can say anything at all about a run on the given driver key
     * (`pgsql`, `mysql`).
     *
     * Part of the contract rather than a detail of whoever asks, and the distinction it draws is
     * NOT the one `supportsCurrentPlatform()` draws. A missing platform build is a tool that
     * would have helped and cannot; an inapplicable driver is a tool that was never going to
     * help here. The first is a named degradation, the second is silence — reporting "squawk
     * was not found, it would have added PostgreSQL rules" on a MySQL run states a loss that
     * does not exist, and under a strict profile it fails a build for something no install on
     * that project could fix.
     *
     * The mirror of the rule the diagnostic already applies to a disabled tool: a decision is
     * not a gap, and neither is a tool that has no jurisdiction here.
     */
    public function supportsDriver(string $driver): bool;

    /**
     * The versions whose output this tool's adapter was written against.
     *
     * Part of the contract rather than an adapter detail, because the locator applies it —
     * a window only the adapter knew about would be a check with no caller.
     */
    public function versionWindow(): ToolVersionWindow;

    /**
     * Judge the first line the binary printed for `--version` — null when it printed nothing.
     *
     * Per tool, because the line is: `squawk 2.61.0`, `psql (PostgreSQL) 18.1`, `pg_format
     * 5.5`. A shared regex over all of them would have to be loose enough to match any of
     * them, and a loose version parser does not fail on a line it does not understand — it
     * finds a number somewhere in it and reports a version nobody printed.
     */
    public function verifyVersion(?string $rawVersionLine): ToolVersionSupport;

    /**
     * The prefix every finding this tool contributes carries in its rule id, e.g. `SQUAWK.`.
     *
     * Part of the CONTRACT rather than a detail of whichever adapter reports the findings, and
     * that placement is the whole fix. The lint runner has to name the suppression sources a run
     * could not verify — an accepted finding from a tool that never answered is not one somebody
     * fixed — and it used to name a constant directly. With one tool registered that was
     * accidentally right; with two it is wrong in both directions at once: a missing PGLS would
     * mark SQUAWK suppressions unverifiable, so a stale baseline line stops being reported and
     * nobody ever deletes it, while the PGLS ones lose the protection entirely.
     *
     * Asking the tool makes the mapping impossible to get wrong, and makes a NEW tool that forgets
     * to answer a type error rather than a silent miscredit.
     */
    public function findingIdPrefix(): string;

    /**
     * How many checks are simply absent without this tool.
     *
     * A COUNT rather than a boolean, because that is what makes an absence arguable. "Not
     * installed" invites a shrug; "seventeen checks nobody is running" is a decision somebody
     * has to make on purpose. It is read from the package's own map of what the tool covers,
     * never from the binary — asking the binary would make the number depend on whether the
     * thing being described is there.
     */
    public function uncoveredCheckCount(): int;
}
