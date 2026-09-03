<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * The versions of an external tool whose behavior SQLens has actually measured.
 *
 * A window, not a floor. A minimum alone says "anything newer will be fine", which is a
 * promise about software nobody here has run: a tool is free to rename a rule, renumber a
 * column, or change its JSON shape in the next major, and every one of those turns a mapped
 * finding into a wrong one — silently, because the parse still succeeds.
 *
 * The bounds are DERIVED FROM MEASUREMENT, never from a changelog. Whatever version the
 * contract spike ran against is the minimum; the ceiling is the next major, because that is
 * where a tool is entitled to change what it promises.
 */
final readonly class ToolVersionWindow
{
    private function __construct(
        /** Inclusive: the oldest version whose output was measured. */
        public string $minimum,
        /** Exclusive: the first version that measurement no longer covers. */
        public string $below,
    ) {}

    /** A measured window — inclusive minimum, exclusive ceiling, both bare `X.Y.Z`. */
    public static function from(string $minimum, string $below): self
    {
        return new self($minimum, $below);
    }

    /** Whether a bare `X.Y.Z` version lies inside this window. */
    public function contains(string $version): bool
    {
        return version_compare($version, $this->minimum, '>=')
            && version_compare($version, $this->below, '<');
    }

    /**
     * The window as it appears in a finding — the reader has to know what to install.
     *
     * Notation rather than prose, so it reads the same in all seven shipped locales and cannot
     * drift from the bounds through a translation.
     */
    public function describe(): string
    {
        return '>= '.$this->minimum.', < '.$this->below;
    }
}
