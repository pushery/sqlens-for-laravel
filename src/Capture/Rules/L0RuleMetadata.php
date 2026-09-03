<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * The shared metadata and documentation shape of the level-0 capture-rule family.
 *
 * Both L0 rules — "no capturable SQL" and "the pretend run threw" — are safety
 * rules at level 0, stable, version-independent, with no downtime class (they
 * describe no DDL). Writing that out twice would be two places to drift; the two
 * differ only in id, message prefix, documentation URL, and examples, so those
 * are the only things a rule passes in. This is the "family metadata built once,
 * not copied" the first L0 rule established for the second.
 */
final class L0RuleMetadata
{
    /**
     * Build the metadata for one L0 rule.
     *
     * `downtimeClass` is null WITH a rationale, not absent: an L0 capture rule
     * fires because SQL could not be captured, so there is no DDL whose downtime
     * behavior it could classify — and a bare null would be indistinguishable
     * from a forgotten field, which the metadata audit rejects.
     */
    public static function for(string $id, string $messagePrefix, string $documentationUrl, string $badExample, string $goodExample): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: $id,
            category: Category::Safety,
            // Level 0 — the lint suite's lowest assurance. "The SQL is capturable"
            // sits under every driver-specific rule, because a rule cannot judge
            // SQL that was never captured.
            level: Level::Capturable,
            // No severity: this is a level-gated safety rule, not a severity-gated
            // security one.
            severity: null,
            // Stable: the capture outcome it reads is a definite fact, not a
            // heuristic over an application's own code, so its false-positive rate
            // is not something a corpus has to establish.
            stability: StabilityTier::Stable,
            deprecation: null,
            // Unbounded, and stated: the check reads a capture outcome, not a
            // server, so no server version changes its answer.
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A level-0 capture rule fires because SQL could not be captured, so it describes no DDL and has no downtime behavior to classify.',
            messagePrefix: $messagePrefix,
            documentationUrl: $documentationUrl,
            suites: [Suite::Lint],
            badExample: $badExample,
            goodExample: $goodExample,
        );
    }

    /**
     * The metadata for a ROUNDTRIP outcome rule — the two lifecycle findings that
     * exist only because the roundtrip replayed `down()` and then `up` again.
     *
     * Same family and same level as the other L0 rules, and the level is the point:
     * a roundtrip is something the user explicitly ASKED for, so hiding its verdict
     * behind a strictness level would be the silent green this package refuses. At
     * level 0 the answer is in scope for every run that produced it.
     *
     * The downtime rationale differs from the capture family's — these fire because
     * a migration's reverse leg misbehaved, not because SQL was uncapturable — and a
     * shared-but-wrong rationale would be worse than none.
     */
    public static function forRoundtrip(string $id, string $documentationUrl, string $badExample, string $goodExample): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: $id,
            category: Category::Safety,
            level: Level::Capturable,
            severity: null,
            stability: StabilityTier::Stable,
            deprecation: null,
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A roundtrip outcome rule judges whether the reverse leg of a migration behaved, which is a question about reversibility rather than about what a statement does to availability while it runs.',
            messagePrefix: 'sqlens.lint',
            documentationUrl: $documentationUrl,
            suites: [Suite::Lint],
            badExample: $badExample,
            goodExample: $goodExample,
        );
    }
}
