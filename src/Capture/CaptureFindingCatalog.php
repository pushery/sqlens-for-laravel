<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Capture\PreScan\IndirectCallDetector;
use Pushery\SQLens\Capture\PreScan\ResultDependentDetector;
use Pushery\SQLens\Capture\PreScan\SchemaIntrospectionGuardDetector;
use Pushery\SQLens\Capture\PreScan\SideEffectFacadeDetector;
use Pushery\SQLens\Capture\Rules\CaptureRule;
use Pushery\SQLens\Capture\Rules\DownFailedRule;
use Pushery\SQLens\Capture\Rules\DownNotInvertibleRule;
use Pushery\SQLens\Capture\Rules\MigrateErrorRule;
use Pushery\SQLens\Capture\Rules\NotCapturableRule;
use Pushery\SQLens\Capture\Rules\PretendErrorRule;
use Pushery\SQLens\Capture\Rules\UndeterminedCaptureRule;
use Pushery\SQLens\Contracts\PreScanDetector;

/**
 * The shipped capture-layer finding producers, in one place.
 *
 * The level-0 rules and the pre-scan detectors are the same set everywhere they are used — the
 * runner constructs them to collect findings, the documentation suite reads their metadata, and
 * the registry export needs them to state what the package documents. Listed separately in each
 * of those places, adding a detector meant remembering all of them; the one that got forgotten
 * was never the one that failed loudly.
 *
 * Each engine's rule set solves the same problem the same way, and for the same reason: what a
 * user runs and what the tests prove have to be the very same objects. Named by shape rather than
 * by class here — this is the driver-neutral core, and an architecture guard holds it to naming no
 * concrete engine. Docblocks included, which is not pedantry: Pint's fully_qualified_strict_types
 * fixer turns a docblock FQCN into a real import, so a `{@see}` is a dependency in waiting.
 *
 * Sorted by rule id rather than by declaration order, so a report's finding order — and the
 * export's entry order — cannot depend on which line a producer was added on.
 */
final readonly class CaptureFindingCatalog
{
    /**
     * The level-0 capture-outcome rules: what became of the capture itself.
     *
     * @return list<CaptureRule>
     */
    public static function rules(): array
    {
        $rules = [
            new DownFailedRule,
            new DownNotInvertibleRule,
            new MigrateErrorRule,
            new NotCapturableRule,
            new PretendErrorRule,
            new UndeterminedCaptureRule,
        ];

        usort($rules, static fn (CaptureRule $a, CaptureRule $b): int => $a->metadata()->id <=> $b->metadata()->id);

        return $rules;
    }

    /**
     * The static pre-scan detectors: what a migration does that a pretend run cannot conclude.
     *
     * @return list<PreScanDetector>
     */
    public static function detectors(): array
    {
        $detectors = [
            new IndirectCallDetector,
            new ResultDependentDetector,
            new SchemaIntrospectionGuardDetector,
            new SideEffectFacadeDetector,
        ];

        usort($detectors, static fn (PreScanDetector $a, PreScanDetector $b): int => $a->metadata()->id <=> $b->metadata()->id);

        return $detectors;
    }

    /**
     * Every capture-layer producer's metadata, rules and detectors together, sorted by id.
     *
     * @return list<CaptureRuleMetadata>
     */
    public static function metadata(): array
    {
        $metadata = array_map(
            static fn (CaptureRule|PreScanDetector $producer): CaptureRuleMetadata => $producer->metadata(),
            [...self::rules(), ...self::detectors()],
        );

        usort($metadata, static fn (CaptureRuleMetadata $a, CaptureRuleMetadata $b): int => $a->id <=> $b->id);

        return $metadata;
    }
}
