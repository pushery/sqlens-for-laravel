<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * The outcome of resolving the active profile: either a valid name and the source
 * it came from, or a rejected value and where it was set. A profile that could not
 * be resolved is a misconfiguration the caller reports — never a silent fall back
 * to the lenient default, which would let a run believe it was strict when it was
 * not (the environment-skew trap).
 */
final readonly class ProfileSelection
{
    private function __construct(
        public ?string $profile,
        public string $source,
        public ?string $rejectedValue,
    ) {}

    /** A resolved profile, tagged with the source that won the precedence. */
    public static function resolved(string $profile, string $source): self
    {
        return new self($profile, $source, null);
    }

    /** A named value that is empty or not a known profile, tagged with where it was set. */
    public static function rejected(string $value, string $source): self
    {
        return new self(null, $source, $value);
    }

    public function isValid(): bool
    {
        return $this->profile !== null;
    }
}
