<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use JsonException;

/**
 * The shipped rule metadata, keyed by id — the one description of what a rule IS.
 *
 * Read from `resources/data/rule-registry.json` rather than composed from the rule objects a
 * second time. A rule's category, level, severity, downtime class and documentation address
 * already have exactly one description in this package, and the artifact holding it is kept
 * byte-identical to the code by its own test. A second walk would be a second thing to keep in
 * step, and the two would agree for a long time before disagreeing once, quietly.
 *
 * It also ships, which is the practical half: a consuming application reads this out of `vendor/`
 * without a documentation directory, a driver boot or a connection.
 *
 * The path is a parameter rather than a constant so the failure paths below are reachable. A
 * refusal nothing can exercise is a refusal nobody has checked, and these two decide whether a
 * catalog is allowed to be incomplete.
 */
final readonly class ShippedRuleMetadata
{
    /** Where the artifact lives, relative to the package root. */
    public const string BUNDLED_FILE = 'resources/data/rule-registry.json';

    /**
     * The artifact that ships with this package.
     *
     * @return array<string, array<array-key, mixed>>
     *
     * @throws UnresolvableRuleCatalog
     */
    public static function shipped(): array
    {
        return self::keyed(dirname(__DIR__, 2).'/'.self::BUNDLED_FILE);
    }

    /**
     * Every row of an artifact, keyed by rule id.
     *
     * @return array<string, array<array-key, mixed>> the decoded rows; `array-key` rather than
     *                                                `string` because that is honestly what JSON
     *                                                decoding yields, and narrowing it here would
     *                                                be a claim about the file rather than about
     *                                                the parser
     *
     * @throws UnresolvableRuleCatalog
     */
    public static function keyed(string $path): array
    {
        $raw = is_file($path) ? file_get_contents($path) : false;

        if ($raw === false) {
            throw UnresolvableRuleCatalog::unreadableRegistry($path);
        }

        try {
            /** @var array{entries?: array<mixed>} $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw UnresolvableRuleCatalog::unreadableRegistry($path, $exception);
        }

        $keyed = [];

        foreach ($decoded['entries'] ?? [] as $entry) {
            $id = is_array($entry) ? $entry['id'] ?? null : null;

            // A row without a usable id cannot be joined to anything, and skipping it silently
            // would make the rule it describes vanish from every catalog with nothing to notice.
            // The refusal is loud for the same reason the missing-row one is.
            if (! is_array($entry) || ! is_string($id)) {
                throw UnresolvableRuleCatalog::malformedRegistryRow($path);
            }

            $keyed[$id] = $entry;
        }

        return $keyed;
    }
}
