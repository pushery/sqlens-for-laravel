<?php

declare(strict_types=1);

namespace Pushery\SQLens\Engine;

use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Reporting\VersionSource;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * The server version a run actually reasoned about, and where it came from — the
 * determinism switch made explicit. It is an assumed pin, a detected version, or a
 * named "could not determine", never a silent guess.
 *
 * A version-dependent rule reads {@see version()} to decide whether it applies; when
 * that is null, the rule is undetermined with {@see reason()}, never a pass — a rule
 * gated on a version it does not know must say so. And when a pin was set but the
 * real server answered a different version, the detected version rides along as
 * {@see skewDetected()} so the run can report the drift as its own finding rather
 * than silently trusting the pin.
 */
final readonly class ResolvedServerVersion
{
    private function __construct(
        public ?ServerVersion $version,
        public VersionSource $source,
        public ?UndeterminedReason $reason = null,
        public ?ServerVersion $skewDetected = null,
        public ?string $unreadablePin = null,
    ) {}

    /**
     * A pin (from the flag or config). The detected version, when present and
     * different, is kept for the skew report — same version is no skew.
     */
    public static function assumed(ServerVersion $pin, ?ServerVersion $detected): self
    {
        $skew = $detected instanceof ServerVersion && $detected->toString() !== $pin->toString()
            ? $detected
            : null;

        return new self($pin, VersionSource::Assumed, null, $skew);
    }

    /** The real version read from the live connection. */
    public static function detected(ServerVersion $version): self
    {
        return new self($version, VersionSource::Detected);
    }

    /**
     * No pin was set and nothing readable came back from the connection — the ordinary
     * shape of a run with nothing to ask. A named undetermined, never a pass.
     */
    public static function unresolvable(): self
    {
        return new self(null, VersionSource::Detected, UndeterminedReason::ServerVersionUnresolvable);
    }

    /**
     * A pin was set and could not be read as a version.
     *
     * The source stays {@see VersionSource::Assumed}: the run was TOLD to reason about
     * a pinned version, and reporting the failure as a detection problem would point
     * the reader at the server instead of at the one setting that needs fixing. The
     * offending text is kept so the report can quote it back — "could not be parsed"
     * without the value sends someone hunting through their config by eye.
     */
    public static function unreadablePin(string $pin): self
    {
        return new self(null, VersionSource::Assumed, UndeterminedReason::UnreadableServerVersionPin, unreadablePin: $pin);
    }

    public function isResolved(): bool
    {
        return $this->version instanceof ServerVersion;
    }

    /** Whether an assumed pin disagreed with the detected version. */
    public function hasSkew(): bool
    {
        return $this->skewDetected instanceof ServerVersion;
    }

    /**
     * The version string for the run header — the resolved version, or a named
     * unknown that is shown, never omitted.
     */
    public function headerVersion(): string
    {
        if ($this->version instanceof ServerVersion) {
            return $this->version->toString();
        }

        // The header carries WHY, not just "unknown". A broken pin and a fast path with
        // nothing to ask both leave the version blank, and only one of them is a mistake
        // somebody has to go and fix — a shared wording would hide it in the other's noise.
        return $this->unreadablePin === null
            ? 'unknown (no server version could be determined)'
            : sprintf('unknown (assume_server_version "%s" could not be read as a version)', $this->unreadablePin);
    }
}
