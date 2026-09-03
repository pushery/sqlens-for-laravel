<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A rule that can contribute a safe fix sequence to the statement it just judged.
 *
 * ## Opt-in, and deliberately so
 *
 * Most rules describe a problem without owning its answer, and forcing every rule to implement this
 * would produce a great many payloads that say nothing — the shape a checklist takes when somebody
 * has to fill every row. A rule implements this when it genuinely knows the safe sequence.
 *
 * ## Null and `none` are different answers
 *
 * Returning null means "this rule has no template for this statement". Returning a payload whose
 * strategy is {@see RemediationStrategy::None} means "this rule looked and there is no safe standard
 * sequence" — a conclusion somebody reached, which a reader can act on. The two arrive at the same
 * empty-looking place from opposite directions, and the report says which.
 *
 * ## It takes the CANONICAL VIEW, and that is a correction
 *
 * The first version of this contract took the finished Finding, reasoning that a payload about a
 * finding should be built from the finding. Building the first real template measured that out: a
 * `CREATE INDEX CONCURRENTLY {{index}} ON {{table}} ({{columns}})` needs three facts, and a finding
 * carries at most one of them — a Location names a SINGLE object, and there is nowhere for the other
 * two to ride. A payload built from a finding would therefore have been a payload with holes in it,
 * which is the one thing a fix template must never be.
 *
 * The view is the same object {@see DerivesDowntimeClass} already receives, for the same reason and
 * with the same guarantee: it is the CANONICAL projection, so a rule reads its table through
 * {@see MigrationStatementView::soleTarget()} and its columns through
 * {@see MigrationStatementView::$keyColumns} — never the raw grammar, which is what the "a second
 * reading is a second chance to disagree" worry was actually about. Reading the same classified
 * facts a second time cannot disagree with the first; re-parsing SQL could, and no rule here can.
 *
 * ## It produces material; it never applies it
 *
 * There is no method here that could execute anything, and the payload it returns names no path and
 * no command. The tool hands structured material to an agent and verifies the result afterwards —
 * that is the whole loop, and an interface with an `apply()` would be the end of it.
 */
interface ProvidesRemediation
{
    /**
     * The safe sequence for this statement, or null when this rule has none for it.
     *
     * Called by the collector for every finding the rule produced from this statement, so a rule
     * that flags twice attaches the same material twice rather than once and arbitrarily.
     *
     * @return RemediationPayload|null null means "no template", never "nothing to do"
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload;
}
