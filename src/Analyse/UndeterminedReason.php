<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

/**
 * Why the parameterization classifier could not answer — as a named value, never as silence.
 *
 * The package's first principle is that a check which cannot run says so with a reason. An
 * `undetermined` with no reason is the same as a skip with no reason: a reader cannot tell whether
 * the classifier looked and failed, or never looked at all. So the reason is part of the verdict's
 * type rather than an optional note somebody may or may not have attached.
 *
 * ## Two reasons, and the two that are deliberately NOT here
 *
 * The planning ticket sketched four names. Two of them turned out to describe things this component
 * cannot or should not say, and inventing a case for them would have produced vocabulary that never
 * fires — the shape this package treats as a defect rather than as harmless spare capacity:
 *
 * - **`binding-array-dynamic`** — "the bindings array was built at runtime, so its size is unknown".
 *   Measured against the design, this is not doubt at all: when the SQL TEXT is constant, nothing
 *   the array holds can change the statement's shape, so `whereRaw('id = ?', $ids)` is parameterized
 *   however `$ids` was assembled. Degrading it would fire on the single most ordinary safe shape in
 *   any Laravel codebase, which is precisely the noise this classifier exists to prevent.
 * `receiver-type-unknown` was in that list too, and it has since arrived — but it is produced ONE
 * LAYER UP, by the collector that recognizes a call site, not by the classifier. The classifier is
 * handed an argument and a scope and never learns who the receiver was. Both live in this enum
 * because a consumer reads one set of reasons; only the producers differ.
 */
enum UndeterminedReason: string
{
    /**
     * The SQL argument's type did not narrow to constant text.
     *
     * A variable, a property, a method call — anything whose value arrives at runtime from outside
     * this call site. The classifier sees ONE call site by design (no data flow across function
     * boundaries), so this is the honest answer for everything it cannot follow, including the case
     * where the value was assembled unsafely one method away.
     */
    case ArgumentTypeUnresolved = 'argument-type-unresolved';

    /**
     * The constant SQL's placeholders and the constant bindings array disagree on how many there are.
     *
     * Deliberately NOT a security finding: the text is constant, so nothing can be injected. It is a
     * bug that will surface at runtime, and the classifier refuses to call the call site
     * parameterized while its own two halves contradict each other.
     */
    case BindingCountMismatch = 'binding-count-mismatch';

    /**
     * The object a fragment method was called on did not resolve to a type.
     *
     * Produced by the fragment collector rather than by the classifier, and it is deliberately NOT
     * the same answer as "the receiver is somebody else's class". A `whereRaw()` on a resolved,
     * foreign type is not a call site at all — that is the false-positive fence, and without it
     * every repository and collection in a codebase would be collected. A receiver that resolved to
     * NOTHING is a different statement: this may well be a query builder, and the honest answer is
     * that nobody can tell.
     *
     * Discarding it silently would be the cheaper choice and the wrong one: it is exactly the case
     * where a real raw-SQL call site disappears from a report that looks complete.
     */
    case ReceiverTypeUnknown = 'receiver-type-unknown';

    /**
     * A column or direction is not known at analysis time, and the request is not visible in it.
     *
     * The identifier rule needs BOTH halves before it reports, because "not known" is the normal
     * state of every sortable listing ever written. When only the first half holds, the allowlist
     * may be one method away — this analysis sees one expression in one scope — so the answer is a
     * named "I cannot tell" rather than a pass.
     */
    case IdentifierOriginUnresolved = 'identifier-origin-unresolved';
}
