<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Turns a `dblint` diagnostic into a SQLens finding — clearly somebody else's check, reported here.
 *
 * ## It translates; it does not map onto SQLens rules
 *
 * A PGLS rule keeps its own identity under this package's prefix. It is deliberately NOT resolved
 * to the SQLens rule that says a similar thing — that correspondence is de-duplication, it belongs
 * to its own ticket, and doing it here would mean two mechanisms deciding what a finding is.
 *
 * ## Why the documentation link stays ours
 *
 * The rule map carries the tool's own help link, and the finding names it in its TEXT. But
 * `documentationUrl` — the address a report renders as "read about this" — stays a page of this
 * package's, exactly as the Squawk adapter does it. A reader following a link from a SQLens report
 * should land somewhere that explains what SQLens did with the finding, including that it came
 * from a tool and what that tool's absence would have meant. The upstream page cannot say any of
 * that, and a report whose links leave the project without warning is a small betrayal of the
 * reader's expectation.
 *
 * ## Why every finding carries the tool version
 *
 * A finding from an external binary is only reproducible if the report says which binary produced
 * it. The version travels in the message rather than being left to the run header, because a
 * finding gets quoted, pasted into an issue and read alone far more often than a header does.
 */
final readonly class PglsFindingMapper
{
    /** The prefix that makes these ids the tool's, held on the tool so nothing declares a second one. */
    public const string ID_PREFIX = PglsTool::FINDING_ID_PREFIX;

    /** The config path a reader edits to change how this adapter behaves. */
    public const string MESSAGE_PREFIX = 'sqlens.tools.pgls';

    /**
     * Preview, like the Squawk adapter's findings and for the same reason: the identity of these
     * ids follows a tool this package does not control, so promising them at the stable tier would
     * be promising something on somebody else's behalf.
     */
    private const StabilityTier STABILITY = StabilityTier::Preview;

    /**
     * The tool's severities, translated once.
     *
     * Not a pass-through, because the two scales are not the same scale. The tool ranks how loudly
     * IT would complain; this package's severity feeds a gate somebody sets in CI. An `ERROR` from
     * a schema linter is a real problem worth failing a build over, so High — but not Critical,
     * which in this package is reserved for findings SQLens established itself and is prepared to
     * stand behind. Deferring to another tool's top rank for that would let an upstream re-rating
     * fail a build nobody changed.
     */
    private const array SEVERITIES = [
        PglsSeverity::Error->value => Severity::High,
        PglsSeverity::Warn->value => Severity::Medium,
        PglsSeverity::Info->value => Severity::Low,
    ];

    public function __construct(private PglsRuleMap $map) {}

    /**
     * One diagnostic, as a finding.
     *
     * A rule outside the measured catalog becomes an `undetermined` rather than being dropped or
     * guessed at: a newer binary that grew a rule is something to hear about, and inventing a
     * severity for it would put a finding into somebody's gate at a level nobody chose.
     */
    public function map(PglsRawFinding $raw, string $toolVersion, string $instance, SubjectContext $context): Finding
    {
        $rule = $this->map->forCategory($raw->category);

        if (! $rule instanceof PglsRule) {
            return $this->unmappedRule($raw, $toolVersion, $instance, $context);
        }

        return Finding::fail(
            self::ID_PREFIX.$rule->rule,
            self::MESSAGE_PREFIX,
            sprintf(
                '%s Reported by the Postgres Language Server %s, which documents this check at %s. %s',
                $rule->summary,
                $toolVersion,
                $rule->helpUri,
                $raw->message,
            ),
            $this->location($raw, $instance),
            Category::Security,
            // The lowest level, and that is a decision rather than a placeholder: strictness levels
            // are this package's own ladder, and a tool's rule did not climb it. Filing an external
            // check at a level SQLens chose for it would make the ladder mean two different things.
            Level::Capturable,
            self::STABILITY,
            DocumentationSite::page('tools/pgls'),
            $context,
            self::SEVERITIES[$rule->severity->value],
        );
    }

    /**
     * The tool could not be run, or could not be read — reported under the adapter's own id.
     *
     * Never silence. A security suite that quietly drops the checks it could not run reports a
     * database as examined when it was not, which is the single failure this package is built to
     * refuse.
     */
    public function unavailable(PglsFailureReason $reason, string $detail, string $instance, SubjectContext $context): Finding
    {
        return Finding::undetermined(
            $reason->value,
            self::MESSAGE_PREFIX,
            sprintf(
                'The Postgres Language Server contributed nothing, so %d schema security check(s) did not run: %s',
                count($this->map->rules),
                $detail,
            ),
            // One reason for every way the tool can contribute nothing, and the specificity is
            // not lost: the finding's own id IS the failure reason, so an unreachable database and
            // an unreadable report are already two different ids a reader can route on. A second
            // axis saying the same thing in coarser words would be one more place to disagree —
            // and the branch that chose between them could only ever be exercised by one arm.
            UndeterminedReason::MissingExternalTool,
            Location::inCatalog('pgsql', $instance, $instance, SchemaObjectType::Database),
            Category::Security,
            Level::Capturable,
            self::STABILITY,
            DocumentationSite::page('tools/pgls'),
            $context,
        );
    }

    /** A rule this build's catalog does not describe — the shape a NEWER tool version takes. */
    private function unmappedRule(PglsRawFinding $raw, string $toolVersion, string $instance, SubjectContext $context): Finding
    {
        return Finding::undetermined(
            self::ID_PREFIX.'UNMAPPED',
            self::MESSAGE_PREFIX,
            sprintf(
                'The Postgres Language Server %s reported "%s", which this build\'s catalog does not describe, so no severity of ours applies to it. Its own message was: %s',
                $toolVersion,
                $raw->category,
                $raw->message,
            ),
            UndeterminedReason::ToolRuleUnmapped,
            $this->location($raw, $instance),
            Category::Security,
            Level::Capturable,
            self::STABILITY,
            DocumentationSite::page('tools/pgls'),
            $context,
        );
    }

    /**
     * Where the finding is, as far as the message allows.
     *
     * A diagnostic carries no file and no line — it judges a schema, not a document — so the object
     * named in the message is the only identity available. When the message is one this build
     * cannot read, the finding is placed on the DATABASE rather than on a guessed object: a reader
     * can act on "somewhere in this database", and cannot act on a confident wrong table.
     */
    private function location(PglsRawFinding $raw, string $instance): Location
    {
        $object = PglsObjectReference::fromMessage($raw->message);

        return $object instanceof PglsObjectReference
            ? Location::inCatalog('pgsql', $instance, $object->name, $object->type)
            : Location::inCatalog('pgsql', $instance, $instance, SchemaObjectType::Database);
    }
}
