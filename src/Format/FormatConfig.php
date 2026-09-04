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
        /**
         * The backends this project has DECIDED not to use, by name.
         *
         * A third state beside "look on the search path" (null) and "it is here" (a path), and the
         * one the other two cannot express: `false` says the project does not want this backend at
         * all. That is not the same fact as a missing binary, and the difference is what a run
         * reports.
         *
         * A backend that is missing is a LOSS — the machine that has it formats differently, the
         * output is committed, and strict tool mode is right to refuse. A backend the project turned
         * off is a DECISION, and reporting it as a loss would tell somebody every run that they are
         * missing the thing they chose to do without.
         *
         * @var list<string>
         */
        public array $disabledBackends = [],
    ) {}

    public static function from(Repository $config): self
    {
        $style = is_array($declared = $config->get('sqlens.format.style')) ? $declared : [];
        $binaries = is_array($declared = $config->get('sqlens.format.binaries')) ? $declared : [];

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
            pgFormatterPath: self::path($binaries['pgformatter'] ?? null),
            sqlFluffPath: self::path($binaries['sqlfluff'] ?? null),
            disabledBackends: self::disabled($binaries),
        );
    }

    /** A configured path, or null to look on the search path. */
    private static function path(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The backends set to `false` — the ones a project decided to do without.
     *
     * Read off the same map the paths come from rather than a second key, because it is the same
     * question: where does this backend live, and `false` is the answer "nowhere, on purpose". A
     * separate list would be a second place to say it and a second place for the two to disagree.
     *
     * Only an exact `false` counts. `null` means "look on the search path" and has meant that since
     * the block existed; reading a falsy null as a decision would turn every default installation
     * into a project that had switched both backends off.
     *
     * @param  array<mixed>  $binaries
     * @return list<string>
     */
    private static function disabled(array $binaries): array
    {
        $off = [];

        foreach (['pgformatter', 'sqlfluff'] as $name) {
            if (($binaries[$name] ?? null) === false) {
                $off[] = $name;
            }
        }

        return $off;
    }

    private static function positiveInt(mixed $value, int $default): int
    {
        // The config validator refuses a non-positive value before any run starts, so this is the
        // second line rather than the first — and it defaults rather than throwing, because a
        // consumer who published `config/sqlens.php` before this block existed has no key at all.
        return is_int($value) && $value > 0 ? $value : $default;
    }
}
