<?php

declare(strict_types=1);

namespace Pushery\SQLens\Engine;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * Resolves the server version a run reasons about, in one fixed precedence:
 *
 *   flag (`--assume-server-version`) → config (`assume_server_version`) → the real
 *   detected version → undetermined.
 *
 * The pin is the whole point of the determinism promise: a version-dependent rule
 * must produce the same result on a dev Mac and in CI, even with no connection to
 * the target instance, so the assumed version is an explicit, versioned input rather
 * than whatever server happens to answer. When neither a pin nor a live version is
 * available, the result is a NAMED undetermined — never a silent default that would
 * let a version-gated rule quietly pass.
 *
 * It is pure: the caller acquires the real version banner (through the one
 * acquisition unit) and hands it in, so the whole precedence is unit-testable with
 * no database, and the parsing lives in the driver-aware version value object.
 */
final readonly class ServerVersionResolver
{
    public function __construct(private Repository $config) {}

    /**
     * @param  string  $driver  the connection's driver key, for driver-aware parsing
     * @param  string|null  $flagPin  the `--assume-server-version` value, or null
     * @param  string|null  $detectedBanner  the real server's raw version banner, or null when no connection answered
     */
    public function resolve(string $driver, ?string $flagPin, ?string $detectedBanner): ResolvedServerVersion
    {
        $detected = $this->parseOrNull($detectedBanner, $driver);
        $pin = $flagPin !== null && $flagPin !== '' ? $flagPin : $this->configPin();

        if ($pin !== null) {
            // parsePin, not parse: a pin is read strictly or refused. The banner scan
            // would turn `18.x` into exactly 18.0 — a version nobody wrote.
            $parsed = ServerVersion::parsePin($pin, $driver);

            // An unparsable pin is a configuration mistake, not a version to trust — it
            // is undetermined under its OWN reason, never a fall-through to detection
            // and never merged with "nothing was pinned". Those two need opposite
            // advice, and merged they read as the same unremarkable line.
            return $parsed instanceof ServerVersion
                ? ResolvedServerVersion::assumed($parsed, $detected)
                : ResolvedServerVersion::unreadablePin($pin);
        }

        return $detected instanceof ServerVersion
            ? ResolvedServerVersion::detected($detected)
            : ResolvedServerVersion::unresolvable();
    }

    private function parseOrNull(?string $banner, string $driver): ?ServerVersion
    {
        if ($banner === null || $banner === '') {
            return null;
        }

        $parsed = ServerVersion::parse($banner, $driver);

        return $parsed instanceof ServerVersion ? $parsed : null;
    }

    /** The configured pin, or null when the run should use the detected version. */
    private function configPin(): ?string
    {
        $configured = $this->config->get('sqlens.assume_server_version');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }
}
