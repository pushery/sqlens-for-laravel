<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A rule that can contribute fix material for the catalog OBJECT it just judged.
 *
 * ## Why this is a second seam and not a widened first one
 *
 * {@see ProvidesRemediation} takes a {@see MigrationStatementView}, and
 * that parameter type is doing work: it guarantees a placeholder is filled from the CANONICALIZED
 * statement, which is what carries this package's determinism claim. An audit rule reads the state
 * of a database and has no statement at all, so it can never satisfy that seam — measured, not
 * assumed: `remediationFor(MigrationStatementView)` is structurally unreachable from a catalog rule.
 *
 * Generalising the parameter to a union was considered and is refused, permanently. It would make
 * the canonical-form guarantee CONDITIONAL — true when the argument happens to be a statement,
 * silent otherwise — which is a weaker contract wearing a more general one's clothes. Two acts, two
 * contracts, each with the guarantee it can actually give.
 *
 * ## What the payload looks like on this side
 *
 * It carries {@see RemediationSubject::SchemaObject}, and that is not a
 * formality: the fields do not all mean the same thing here. There is no deploy whose effect a
 * downtime class could describe, and no "this migration" for a step to edit — the fix for a state
 * IS a new migration. A payload that gets either wrong is REFUSED by the validator rather than
 * rendered, so this contract cannot quietly produce a template that reads like a statement's.
 *
 * ## The precondition is WRITTEN, not encoded in the return type
 *
 * A rule is asked only about an object it itself reported on. That is a promise the caller keeps,
 * and it is stated here in prose on purpose. The lint side left the same precondition implicit and
 * encoded it as a non-nullable return type — "I am never asked without reason" — and when a second
 * caller appeared, seven rules answered confidently about statements they had never flagged. A
 * sentence somebody can read outlives a type that only holds while the call graph does.
 *
 * So: `null` is always a legitimate answer, including for an object this rule has nothing to say
 * about. Null means "no template", never "nothing to do" — the second is
 * {@see RemediationStrategy::None}, which is a conclusion somebody
 * reached and a reader can act on.
 *
 * ## It produces material; it never applies it
 *
 * The same invariant the first seam carries. There is no method here that could execute anything,
 * and the payload names no path and no command.
 */
interface ProvidesSchemaObjectRemediation
{
    /**
     * The fix material for this object, or null when this rule has none for it.
     *
     * @return RemediationPayload|null null means "no template", never "nothing to do"
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload;
}
