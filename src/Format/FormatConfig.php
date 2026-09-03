<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Illuminate\Contracts\Config\Repository;

/**
 * The format block, read once and turned into values the rest of the suite can use.
 *
 * The same reason `GuardProfile` exists one namespace over: a backend that read
 * `config('sqlens.format.style.indent')` would carry a verdict its own tests cannot see, because the
 * value arrives from a global. Everything here takes typed values, and this is the only place that
 * reads the array.
 */
final readonly class FormatConfig
{
    public function __construct(
        public string $backend,
        public string $dialect,
        public FormatStyle $style,
        public int $timeout,
        public ?string $pgFormatterPath,
        public ?string $sqlFluffPath,
    ) {}

    public static function from(Repository $config): self
    {
        $style = is_array($declared = $config->get('sqlens.format.style')) ? $declared : [];

        return new self(
            backend: is_string($backend = $config->get('sqlens.format.backend')) ? $backend : 'auto',
            dialect: is_string($dialect = $config->get('sqlens.format.dialect')) ? $dialect : 'auto',
            style: new FormatStyle(
                indent: self::positiveInt($style['indent'] ?? null, 4),
                uppercaseKeywords: ($style['uppercase_keywords'] ?? true) === true,
                leadingCommas: ($style['leading_commas'] ?? false) === true,
                lineWidth: self::positiveInt($style['line_width'] ?? null, 100),
            ),
            timeout: self::positiveInt($config->get('sqlens.format.timeout'), 15),
            pgFormatterPath: self::path($config->get('sqlens.format.binaries.pgformatter')),
            sqlFluffPath: self::path($config->get('sqlens.format.binaries.sqlfluff')),
        );
    }

    /** A configured path, or null to look on the search path. */
    private static function path(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function positiveInt(mixed $value, int $default): int
    {
        // The config validator refuses a non-positive value before any run starts, so this is the
        // second line rather than the first — and it defaults rather than throwing, because a
        // consumer who published `config/sqlens.php` before this block existed has no key at all.
        return is_int($value) && $value > 0 ? $value : $default;
    }
}
