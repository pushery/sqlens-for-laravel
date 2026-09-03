<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * One diagnostic as the tool reported it, before SQLens has decided anything about it.
 *
 * The shape was measured against 0.25.7:
 *
 * ```json
 * {"severity":"warning","message":"Function `public.f` has a role mutable search_path",
 *  "category":"splinter/security/functionSearchPathMutable"}
 * ```
 *
 * Three fields, and notably NO file and no line. That is not an omission — `dblint` judges a
 * database schema rather than a document, so there is nothing for a position to point at. The
 * package's `ToolPositionMapper` therefore does not apply here, and the identity of a finding has
 * to come from the object named in the message instead.
 *
 * The severity arrives lower-cased on a diagnostic (`warning`) while the catalog spells it upper
 * (`WARN`) — two vocabularies for the same thing, in the same program. Reconciling them is done
 * once, here, against the measured pairs, rather than by lower-casing everything and hoping.
 */
final readonly class PglsRawFinding
{
    /** The diagnostic severities measured on the wire, mapped onto the catalog's vocabulary. */
    private const array WIRE_SEVERITIES = [
        'error' => PglsSeverity::Error,
        'warning' => PglsSeverity::Warn,
        'info' => PglsSeverity::Info,
    ];

    public function __construct(
        /** The full category string, e.g. `splinter/security/functionSearchPathMutable`. */
        public string $category,
        public PglsSeverity $severity,
        public string $message,
    ) {}

    /**
     * Read one entry of the report, or null when it is not the shape this adapter was written for.
     *
     * Null rather than a partially-filled finding: a diagnostic missing its category cannot be
     * matched to a rule, and one missing its severity cannot be ranked. Either way there is
     * nothing to report except that the report was not readable, and the caller turns that into
     * {@see PglsFailureReason::OutputUnreadable}.
     */
    public static function fromReportEntry(mixed $entry): ?self
    {
        if (! is_array($entry)) {
            return null;
        }

        $category = $entry['category'] ?? null;
        $message = $entry['message'] ?? null;
        $severity = $entry['severity'] ?? null;

        if (! is_string($category) || $category === '' || ! is_string($message) || ! is_string($severity)) {
            return null;
        }

        $mapped = self::WIRE_SEVERITIES[$severity] ?? null;

        // An unrecognized severity is a report shape nobody measured, not a mild finding. Defaulting
        // it to the gentlest level is how a tool that grew a fourth severity would have every
        // finding at that level quietly filed as the least urgent one.
        if (! $mapped instanceof PglsSeverity) {
            return null;
        }

        return new self($category, $mapped, $message);
    }
}
