<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Canonical\Stages\IdentifierNormalizer;
use Pushery\SQLens\Canonical\Stages\KeywordCasingNormalizer;
use Pushery\SQLens\Canonical\Stages\StatementClassifier;
use Pushery\SQLens\Canonical\Stages\TransactionContextResolver;
use Pushery\SQLens\Canonical\Stages\WhitespaceNormalizer;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * The ONE place the canonicalization stage order is declared.
 *
 * The order is load-bearing and every consumer must run the same one — the
 * capture decorator, the drift comparison, the golden corpus — or two of them
 * would produce different canonical forms for the same input, which is the
 * determinism break the third principle forbids. So it lives here, assembled
 * once, rather than being re-listed at each call site where a copy could fall out
 * of step.
 *
 * The order is not arbitrary:
 *
 *   1. Whitespace first, so every later stage sees one canonical spacing and
 *      never has to account for the formatting the grammar happened to emit.
 *   2. Identifier normalization before keyword casing, so an identifier is
 *      recognized and settled before the casing stage runs — otherwise a column
 *      named `order` could be upper-cased as if it were the keyword.
 *   3. Keyword casing next, over the now-settled identifiers.
 *   4. Transaction context, read from the normalized statement stream.
 *   5. Classification last, because it matches shapes against the fully
 *      normalized statement — classifying raw grammar output would couple the
 *      classifier to formatting.
 *
 * The driver's own stages run after the generic ones: a driver adds a stage only
 * for a quirk the generic pipeline cannot express, and it expresses it over the
 * already-normalized statement.
 */
final class CanonicalizationPipeline
{
    /**
     * The generic stages, in canonical order, for a driver — the exact list every
     * consumer must run.
     *
     * @return list<CanonicalizationStage>
     */
    public static function stagesFor(DriverCanonicalization $driver): array
    {
        return [
            new WhitespaceNormalizer($driver),
            new IdentifierNormalizer($driver),
            new KeywordCasingNormalizer($driver),
            new TransactionContextResolver($driver),
            new StatementClassifier($driver),
            ...$driver->stages(),
        ];
    }

    /** A Canonicalizer wired with the standard pipeline for the driver. */
    public static function forDriver(DriverCanonicalization $driver): Canonicalizer
    {
        return new Canonicalizer(self::stagesFor($driver));
    }
}
