<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\FunctionLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * Where a reasoned `#[RawSql]` sits, as a LINE RANGE rather than as a name.
 *
 * ## The two shapes that had no name to join on
 *
 * {@see JustificationCollector} joins by name — `App\Report`, `App\Report::build`. That works
 * wherever the annotated thing has a name a call site inside it also reports. Two very ordinary
 * shapes do not:
 *
 * - **A free function.** `#[RawSql]` declares `TARGET_FUNCTION`, so PHP accepts the annotation
 *   without a word, and nothing read it: the collector visited class nodes only. Worse, the call
 *   site's own scope name is `null` outside a class, so even collecting the function would not have
 *   joined.
 * - **A closure at file scope.** Every Pest test body is one. There the duty was not merely hard to
 *   discharge, it was impossible — the only remaining answer was an `exclude_paths` entry over the
 *   whole test directory, which silences far more than the finding.
 *
 * ## Why a range, and not another name
 *
 * A closure has no name at all, so there is nothing for a name join to compare. Position is the only
 * identity it has — and once position is the mechanism for one of them it is the honest mechanism
 * for both, because a span says exactly what the annotation means: everything written inside this
 * function-like is covered, the same way a method-level annotation covers its method.
 *
 * Nested closures come out right for free: a closure inside an annotated function is inside its
 * span. So does a call in a method of a class declared inside an annotated function.
 *
 * ## One collector for four node shapes, and the registry really does allow it
 *
 * `getNodeType()` returns the INTERFACE. PHPStan's collector registry resolves a node's collectors
 * through `class_parents` + `class_implements` of the node's actual class
 * (`PHPStan\Collectors\Registry::getCollectors()` via `ExtensionClassHelper`), so one registration on
 * {@see FunctionLike} is reached for {@see Function_}, {@see Closure}, {@see ArrowFunction} and
 * {@see ClassMethod} alike.
 *
 * ⚠️ {@see JustificationCollector} says the opposite — *"PHPStan's registry does not walk
 * subclasses, so one collector per node shape is the rule"* — and that sentence is what kept the
 * two missing shapes unreachable for a version longer than they had to be. It has been corrected
 * there; this is the measurement it was corrected against.
 *
 * ## A class method belongs to the OTHER channel, and this one skips it
 *
 * {@see ClassMethod} implements {@see FunctionLike}, so it arrives here too — and it is the one
 * shape the name collector already owns. Recording it in both was harmless for JUSTIFICATION (two
 * channels agreeing that a call is covered is still one answer) and wrong for the expiry direction:
 * {@see StaleRawSqlReasonRule} reports the ANNOTATION, so one attribute produced two findings on the
 * same line, one naming the method and one saying "here".
 *
 * Measured, not foreseen — the arm over the stale fixture caught it. Single ownership per shape is
 * the rule now: the name collector takes classes and methods, this one takes everything else PHP
 * lets the attribute sit on.
 *
 * @implements Collector<FunctionLike, array{from: int, to: int, rawSql: bool, interpolation: bool}|null>
 */
final readonly class JustificationSpanCollector implements Collector
{
    /** The one unit that decides what counts as a reason, shared with the name collector. */
    public function __construct(private RawSqlReason $reason = new RawSqlReason) {}

    public function getNodeType(): string
    {
        return FunctionLike::class;
    }

    /**
     * The line range this annotation covers, or null when it carries no reasoned `#[RawSql]`.
     *
     * The range is the whole node — signature included — because a call site can only be INSIDE the
     * body, so a range that starts at the attribute is never too wide and is easier to reason about
     * than one that tries to start at the brace.
     *
     * The two flags say WHICH question the annotation answered, and they are independent. `reason:`
     * says why raw SQL was chosen; `interpolation:` says why a runtime value is in the statement's
     * text. A span carrying only the second is not a justification for the policy rule, and a span
     * carrying only the first must not clear an injection finding — so the span is recorded once and
     * each reader filters on its own flag.
     *
     * A policy that refuses one argument leaves the other standing: they are answers to different
     * questions, and one being unsatisfactory says nothing about the other.
     *
     * @return array{from: int, to: int, rawSql: bool, interpolation: bool}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // No `instanceof FunctionLike` here: the generic annotation above already tells PHPStan the
        // node type, and re-checking it is a branch no run can enter — which the analyzer reports
        // rather than tolerates. `ClassMethod` is a different question: it IS reached, and it is the
        // one shape the name collector owns.
        if ($node instanceof ClassMethod) {
            return null;
        }

        $rawSql = $this->reason->isPresentIn($node->getAttrGroups(), $scope);
        $interpolation = $this->reason->justifiesInterpolationIn($node->getAttrGroups(), $scope);

        if (! $rawSql && ! $interpolation) {
            return null;
        }

        $from = $node->getStartLine();
        $to = $node->getEndLine();

        // A node whose position the parser could not give is not a span anybody can be inside. -1 is
        // what php-parser answers without position attributes, and a range of -1..-1 would either
        // cover nothing (harmless) or, read the wrong way round, cover a file (not harmless).
        // Bound to ONE line, deliberately. Wrapped across three, the `? null` arm sits on a line of
        // its own that no coverage driver ever marks as executed — a known trap in this repository —
        // so the span is named first and the guard stays a single statement.
        $span = ['from' => $from, 'to' => $to, 'rawSql' => $rawSql, 'interpolation' => $interpolation];

        return $from < 1 || $to < $from ? null : $span;
    }
}
