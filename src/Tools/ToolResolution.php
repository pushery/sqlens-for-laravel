<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * How the locator resolved an external tool — and, crucially, WHY it is absent when
 * it is. "No silent green" reaches the tool layer: a tool that could not be found is
 * never an anonymous skip; it points at one of these named states.
 *
 * The distinction between NotFound and UnsupportedPlatform is the one that matters
 * for strict mode. A tool the platform can run but that is not installed is a
 * fixable CI misconfiguration — strict mode makes it an error. A tool with no build
 * for this platform at all (Squawk has no Windows binary) is a documented reality,
 * not a fixable absence, so it degrades with a named reason but never fails a strict
 * run — otherwise every Windows CI would fail for a tool it could never have.
 */
enum ToolResolution: string
{
    /** Found at the path the configuration named. */
    case ConfiguredPath = 'configured_path';

    /** Found on the system `$PATH`. */
    case SystemPath = 'system_path';

    /**
     * The configuration named a path and that path is not a runnable binary.
     *
     * Its own case rather than a fall-through to `$PATH`, and that distinction is the whole
     * point of pinning: a project that names a path has said WHICH binary it wants. Quietly
     * running a different one because the named one did not answer is the exact shape of
     * "it behaves differently on my machine" — the configuration would look honored while
     * the result came from somewhere else entirely.
     */
    case ConfiguredPathNotExecutable = 'configured_path_not_executable';

    /** Not found, though this platform could run it — a fixable absence. */
    case NotFound = 'not_found';

    /**
     * The binary was found and could not be made to say which version it is.
     *
     * Not available, even though something IS there. The output of an external tool is
     * parsed against a shape that was measured from one version; running a binary whose
     * identity is unknown means parsing an unknown shape, and that does not fail loudly —
     * it maps a finding to the wrong rule, or to the wrong line, and looks fine doing it.
     */
    case VersionUnreadable = 'version_unreadable';

    /**
     * The binary said which version it is, and it is outside the window that was measured.
     *
     * The most dangerous of the absences, and the reason it is not simply allowed: a tool
     * one major ahead still runs, still exits 0, still prints JSON — with a renamed rule or
     * a renumbered field. That is the shape of a green run that checked something else.
     */
    case VersionUnsupported = 'version_unsupported';

    /** No build exists for this platform — a named degradation, never a strict failure. */
    case UnsupportedPlatform = 'unsupported_platform';

    /**
     * The project switched this tool off.
     *
     * Not an absence, and that distinction is the whole reason it is its own state. Every other
     * state here says something SQLens discovered; this one says something the project DECIDED,
     * and reporting a decision back as a problem every run is how a tool teaches people to stop
     * reading it. It never fails a strict run either — strict mode asks whether the amplifiers a
     * project WANTS ran, not whether it wants them.
     */
    case Disabled = 'disabled';

    /** Whether the tool is available to run. */
    public function isAvailable(): bool
    {
        return $this === self::ConfiguredPath || $this === self::SystemPath;
    }

    /**
     * Whether this absence should fail a strict run — a fixable one, never a platform reality.
     *
     * A named path that does not run belongs here for a stronger reason than a plain not-found:
     * the project asked for that exact binary, so its absence is a broken promise rather than a
     * missing optional extra.
     *
     * Both version states belong here too, and that is the point of having them. An installed
     * tool of the wrong version is the one absence a CI is most likely to have without knowing:
     * the install step succeeded, the binary is on `$PATH`, and nothing looks wrong. Strict mode
     * exists to say "the amplifier really ran", and a build we have never measured did not.
     */
    public function failsStrict(): bool
    {
        return in_array($this, [self::NotFound, self::ConfiguredPathNotExecutable, self::VersionUnreadable, self::VersionUnsupported], true);
    }
}
