<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Settings;

/**
 * What one server variable should be, on one engine, from one version on — read from the matrix.
 *
 * The point of the file behind it is that no rule hard-codes its own expectation. A value written
 * into a rule is invisible to review, undiffable across versions, and carries no source; the same
 * value in a data file is all three.
 */
final readonly class ServerSettingExpectation
{
    private function __construct(
        public string $variable,
        public string $driver,
        public string $minVersion,
        public ?string $maxVersion,
        public string $vendorDefault,
        /**
         * What SQLens expects, or null when the value is worth READING but not judging.
         *
         * Null is a real answer rather than a gap: `lower_case_table_names` depends on the
         * deployment's filesystem, so a rule that judged it would be wrong on half of them. What is
         * still worth reporting is a MISMATCH between environments, which needs the value without
         * needing an opinion about it.
         */
        public ?string $expectation,
        public SettingChangeCost $changeable,
        public string $sourceUrl,
        public string $note,
    ) {}

    /** @param  array<string, mixed>  $row */
    public static function fromArray(array $row): self
    {
        return new self(
            self::text($row, 'variable'),
            self::text($row, 'driver'),
            self::text($row, 'min_version'),
            self::nullableText($row, 'max_version'),
            self::text($row, 'vendor_default'),
            self::nullableText($row, 'sqlens_expectation'),
            SettingChangeCost::from(self::text($row, 'changeable')),
            self::text($row, 'source_url'),
            self::text($row, 'note'),
        );
    }

    /** Whether this entry is worth judging, as opposed to merely reporting. */
    public function isJudged(): bool
    {
        return $this->expectation !== null;
    }

    /** @param  array<string, mixed>  $row */
    private static function text(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /** @param  array<string, mixed>  $row */
    private static function nullableText(array $row, string $key): ?string
    {
        $value = $row[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
