<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Which finding-id prefixes a run could not verify, because the tool behind them never answered.
 *
 * ## Why this is a class and not four lines in the runner
 *
 * It was those four lines, and they were wrong in a way nothing could see. They named ONE prefix
 * for any unavailable tool — correct by accident while exactly one tool was registered, and wrong
 * in both directions the moment a second one was:
 *
 *   - the ABSENT tool's suppressions lost their shield, so a baseline line that comes straight back
 *     on the next machine reads as safe to delete;
 *   - the PRESENT tool's suppressions gained one they should not have, so a genuinely stale line is
 *     never reported and the file never shrinks.
 *
 * Neither is visible in a report. Both look like ordinary output.
 *
 * The lines lived inside a long private method, which is the other half of why they survived: there
 * was nowhere to point a test. Naming the rule gives it one — and a test that registers TWO tools
 * can finally fail, which is the thing no test in this suite could do before.
 */
final readonly class UnverifiableToolPrefixes
{
    /**
     * The prefixes to shield, one per unavailable tool, de-duplicated and in registration order.
     *
     * Each prefix is asked of its OWN tool. That is the entire correction, and it is why a tool
     * added later cannot be miscredited: a `Tool` that does not answer is a type error rather than
     * a silently wrong entry.
     *
     * @param  list<ToolDiagnostic>  $diagnostics
     * @return list<string>
     */
    public static function from(array $diagnostics): array
    {
        $prefixes = [];

        foreach ($diagnostics as $diagnostic) {
            if (! $diagnostic->isAvailable()) {
                $prefixes[] = $diagnostic->tool->findingIdPrefix();
            }
        }

        return array_values(array_unique($prefixes));
    }
}
