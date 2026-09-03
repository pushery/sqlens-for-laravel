<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

/**
 * The governance contract "new rules land as preview", cast into a type before
 * the first rule exists. Introduced later, every already-built rule would be
 * implicitly stable — the exact mistake the contract prevents.
 *
 * The backed values are public API and appear in the docs and the output. The
 * default for a new rule is preview (opt-in); promotion to stable happens only
 * in a major.
 */
enum StabilityTier: string
{
    case Stable = 'stable';
    case Preview = 'preview';
    case Experimental = 'experimental';

    /** The default tier for a rule that does not declare one — deliberately preview, never stable. */
    public static function default(): self
    {
        return self::Preview;
    }

    /** Only stable rules run by default; preview and experimental need an opt-in in config. */
    public function isEnabledByDefault(): bool
    {
        return $this === self::Stable;
    }
}
