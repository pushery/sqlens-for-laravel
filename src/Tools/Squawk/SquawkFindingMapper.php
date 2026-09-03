<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\MigrationDirection;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\ToolPosition;
use Pushery\SQLens\Tools\ToolPositionResult;

/**
 * Turns one of the tool's raw findings into a SQLens finding.
 *
 * The translation is one-directional and deliberately incomplete: the tool's category words,
 * its severity scale and its own numbering do not come across. Two scales in one report leave
 * the reader working out which one a number came from, so a finding that arrives here is
 * re-described in SQLens's vocabulary — or, where the map has no answer, reported as
 * undetermined rather than given one.
 *
 * The origin stays visible. A tool finding carries the `SQUAWK.` prefix in its id and links to
 * the rule upstream when SQLens has no page of its own, so nothing here can be mistaken for a
 * rule this package wrote.
 */
final readonly class SquawkFindingMapper
{
    /**
     * The namespace the tool's findings live in.
     *
     * Its own prefix, because a reader has to be able to tell where a verdict came from — and
     * because a suppression written against `SQUAWK.require-lock-timeout` must not silence the
     * SQLens rule that says the same thing, or the reverse.
     */
    public const string ID_PREFIX = 'SQUAWK.';

    public const string MESSAGE_PREFIX = 'sqlens.tools.squawk';

    /**
     * Everything from a tool ships as PREVIEW, not stable.
     *
     * The tool's rule set moves on its own schedule, and its wording changes with it. Calling
     * that stable would be promising something this package does not control.
     */
    private const StabilityTier STABILITY = StabilityTier::Preview;

    public function __construct(
        private SquawkRuleMap $map,
        private string $projectRoot,
    ) {}

    /**
     * The finding, or null when the map says this rule is deliberately not reported.
     *
     * Null is a real answer here rather than a failure: a rule SQLens has decided not to cover
     * should not reach a report through the back door of an amplifier.
     */
    public function map(SquawkRawFinding $raw, ToolPositionResult $position, SubjectContext $context): ?Finding
    {
        $mapping = $this->map->for($raw->ruleName);

        if (! $mapping instanceof SquawkRuleMapping) {
            return $this->unmappedRule($raw, $position, $context);
        }

        if (! $mapping->surfaces()) {
            return null;
        }

        $placed = $position->position;

        if (! $placed instanceof ToolPosition) {
            return $this->unplaceable($raw, $mapping, $context);
        }

        return $this->finding($raw, $mapping, $placed, $context);
    }

    /**
     * The tool contributed nothing for one migration, and why.
     *
     * A degradation of the TOOL, never of the run: the core rules already produced their verdicts
     * on this migration and are untouched. It names the migration, because a run over forty of
     * them that said only "squawk failed" leaves a reader with nowhere to look.
     */
    public function degradation(SquawkFailureReason $reason, CaptureResult $result, SubjectContext $context, string $detail = ''): Finding
    {
        return Finding::undetermined(
            $reason->value,
            self::MESSAGE_PREFIX,
            trim(sprintf(
                'squawk contributed nothing for %s%s',
                $result->migrationClass,
                $detail === '' ? '.' : ': '.$detail,
            )),
            UndeterminedReason::MissingExternalTool,
            Location::inMigration($result->file, $result->migrationClass, 0, MigrationDirection::Up, $this->projectRoot),
            Category::Safety,
            Level::Capturable,
            self::STABILITY,
            DocumentationSite::page('tools/squawk'),
            $context,
        );
    }

    /**
     * A rule this build's map does not describe — the shape a NEWER tool version takes.
     *
     * Reported, not dropped, and not promoted to a failure either. A pipeline that upgraded the
     * binary would otherwise see a finding appear from nowhere, at a level and category nobody
     * chose; and dropping it would hide that the tool now checks something this package has not
     * looked at.
     */
    private function unmappedRule(SquawkRawFinding $raw, ToolPositionResult $position, SubjectContext $context): Finding
    {
        return Finding::undetermined(
            self::ID_PREFIX.$raw->ruleName,
            self::MESSAGE_PREFIX,
            sprintf(
                'squawk reported "%s", a rule this build does not describe, so no category or level of ours applies to it. Its own message was: %s',
                $raw->ruleName,
                $raw->message,
            ),
            UndeterminedReason::ToolRuleUnmapped,
            $this->location($position->position),
            // Safety and level 0: the finding is about the RUN not knowing something, which is
            // where every capture-layer notice sits. Guessing the level of an unknown rule would
            // be exactly the invention this case exists to avoid.
            Category::Safety,
            Level::Capturable,
            self::STABILITY,
            DocumentationSite::page('tools/squawk'),
            $context,
        );
    }

    /** A finding whose position could not be traced back to a statement. */
    private function unplaceable(SquawkRawFinding $raw, SquawkRuleMapping $mapping, SubjectContext $context): Finding
    {
        return Finding::undetermined(
            self::ID_PREFIX.$raw->ruleName,
            self::MESSAGE_PREFIX,
            sprintf(
                'squawk reported "%s" at a position that could not be traced back to a statement, so it is reported without one. Its own message was: %s',
                $raw->ruleName,
                $raw->message,
            ),
            UndeterminedReason::ToolPositionUnmappable,
            $this->toolCallsite(),
            $mapping->category ?? Category::Safety,
            $mapping->level ?? Level::Capturable,
            self::STABILITY,
            $this->documentationUrl($mapping),
            $context,
            $mapping->severity,
        );
    }

    private function finding(SquawkRawFinding $raw, SquawkRuleMapping $mapping, ToolPosition $position, SubjectContext $context): Finding
    {
        $finding = Finding::fail(
            self::ID_PREFIX.$raw->ruleName,
            self::MESSAGE_PREFIX,
            $raw->message,
            $this->location($position),
            // Never null on a surfacing rule — the loader refuses a map that says otherwise, so
            // the coalesce is a type narrowing rather than a fallback with an opinion.
            $mapping->category ?? Category::Safety,
            $mapping->level ?? Level::Capturable,
            self::STABILITY,
            $this->documentationUrl($mapping),
            $context,
            $mapping->severity,
        );

        // Attached only when the map states one. A downtime class is what a deploy gate branches
        // on, so a guessed one is worse than none: the gate would let something through on a
        // number nobody established.
        return $mapping->downtimeClass instanceof DowntimeClass
            ? $finding->withDowntimeClass($mapping->downtimeClass)
            : $finding;
    }

    /**
     * The page a reader is sent to.
     *
     * Our own rule page when the map names a SQLens rule that covers the same ground — the
     * reader wants the explanation, and ours is the one written for this report. Otherwise the
     * rule upstream, because sending them to a page this package has never written would be a
     * dead link dressed as documentation.
     */
    private function documentationUrl(SquawkRuleMapping $mapping): string
    {
        return $mapping->sqlensRule === null
            ? $mapping->sourceUrl
            : DocumentationSite::page('rules/'.strtolower(str_replace(['.', '_'], '-', $mapping->sqlensRule)));
    }

    /** The tool's own callsite, for a finding that could not be placed on a statement. */
    private function toolCallsite(): Location
    {
        return Location::inCallsite('tool:squawk', 0, 'squawk', $this->projectRoot);
    }

    private function location(?ToolPosition $position): Location
    {
        if (! $position instanceof ToolPosition) {
            return $this->toolCallsite();
        }

        return Location::inMigration(
            $position->file,
            $position->migrationClass,
            $position->statementIndex,
            $position->direction,
            $this->projectRoot,
        );
    }
}
