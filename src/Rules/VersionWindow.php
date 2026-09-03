<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

/**
 * A version window as pure comparison logic: an optional minVersion and
 * maxVersion, and the question of whether a given ServerVersion falls inside.
 * Once the rule contract requires a window, a cargo-culted rule for an old
 * engine becomes structurally impossible.
 *
 * This VO only compares — it does not parse (that is ServerVersion) and it does
 * not bind to the contract. matches() is inclusive at both bounds.
 */
final readonly class VersionWindow
{
    public function __construct(
        public ?ServerVersion $minVersion,
        public ?ServerVersion $maxVersion,
    ) {}

    /** A window with no bounds — matches every version. */
    public static function unbounded(): self
    {
        return new self(null, null);
    }

    /**
     * The window as a sentence — what a reader is told when a rule did not run.
     *
     * Named here rather than at the call site because a window is what knows its own bounds, and a
     * caller reformatting them would be a second spelling of the same fact. "Skipped by version"
     * tells somebody that something was skipped; "PostgreSQL 18 or newer" tells them whether to
     * care.
     */
    public function describe(): string
    {
        return match (true) {
            $this->minVersion instanceof ServerVersion && $this->maxVersion instanceof ServerVersion => sprintf(
                '%s through %s',
                $this->minVersion->toString(),
                $this->maxVersion->toString(),
            ),
            $this->minVersion instanceof ServerVersion => $this->minVersion->toString().' or newer',
            $this->maxVersion instanceof ServerVersion => $this->maxVersion->toString().' or older',
            // An unbounded window never reaches a caller that needs a sentence, but answering is
            // cheaper than a null nobody expects.
            default => 'any version',
        };
    }

    /**
     * Whether this window depends on the server version at all. An unbounded window is
     * version-INDEPENDENT: it runs whatever the version, even when none could be
     * determined. A bounded window is version-DEPENDENT, so a rule carrying it cannot be
     * judged without a version — the engine turns it into an undetermined finding rather
     * than guessing a default (the difference the fast path turns on).
     */
    public function isBounded(): bool
    {
        return $this->minVersion instanceof ServerVersion || $this->maxVersion instanceof ServerVersion;
    }

    public static function from(ServerVersion $min): self
    {
        return new self($min, null);
    }

    public static function upTo(ServerVersion $max): self
    {
        return new self(null, $max);
    }

    public static function between(ServerVersion $min, ServerVersion $max): self
    {
        return new self($min, $max);
    }

    /** Inclusive at both bounds, gapless. An unbounded window matches everything. */
    public function matches(ServerVersion $version): bool
    {
        if ($this->minVersion instanceof ServerVersion && $version->isBelow($this->minVersion)) {
            return false;
        }

        return ! $this->maxVersion instanceof ServerVersion || ! $this->maxVersion->isBelow($version);
    }
}
