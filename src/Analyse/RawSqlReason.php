<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Attribute;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use Pushery\SQLens\Attributes\RawSql;

/**
 * Whether an attribute list carries a `#[RawSql]` whose reason this run accepts.
 *
 * ## Why it is a unit rather than a method on the collector that had it
 *
 * It answers the question two collectors ask — {@see JustificationCollector} by name and
 * {@see JustificationSpanCollector} by line range — and two copies of "what counts as a reason"
 * would let one channel accept an annotation the other refuses. A project meeting that would be
 * right to call it a bug, and neither collector's tests would see it: each would be green about its
 * own half.
 *
 * ## Read from the SYNTAX, never from reflection
 *
 * The obvious implementation asks `ReflectionClass::getAttributes()`, and it is the wrong one here:
 * that needs the analyzed class to be LOADABLE, so a project whose classes want a booted framework
 * would silently lose every justification — every annotated call site would start reporting, which
 * is the shape that gets an analyzer switched off within a day.
 *
 * The attribute is therefore read off the node's own `attrGroups`. Nothing is autoloaded and nothing
 * is instantiated, so a malformed attribute cannot execute anything either.
 */
final readonly class RawSqlReason
{
    /**
     * The run's policy, because WHAT counts as a reason is a configured question.
     *
     * Read here rather than in the rule, and the placement is the whole design: a reason the mode
     * refuses is simply not collected, so the rule downstream needs no second notion of "reasoned"
     * and cannot drift from this one. The default instance means an unconfigured run behaves
     * identically to one that spelled the defaults out.
     */
    public function __construct(private AnalyseConfig $config = new AnalyseConfig) {}

    /**
     * Does this attribute list carry a `#[RawSql]` whose reason says anything?
     *
     * An annotation with an empty reason answers `false`. The constructor makes the argument
     * required and cannot make it meaningful — `reason: ''` satisfies PHP and states nothing, and
     * accepting it is how a justification requirement becomes a keystroke everybody learns and
     * nobody means.
     *
     * @param  array<array-key, Node\AttributeGroup>  $groups
     */
    public function isPresentIn(array $groups, Scope $scope): bool
    {
        foreach ($groups as $group) {
            foreach ($group->attrs as $attribute) {
                if ($scope->resolveName($attribute->name) === RawSql::class && $this->hasRealReason($attribute)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether the annotation's reason is one the run's policy accepts.
     *
     * Only text the SYNTAX already carries is read — a literal, or literals joined with `.`. A
     * constant or a variable is not resolved, and that is deliberate rather than lazy: resolving one
     * would mean evaluating project code during analysis. The consequence lands in the safe
     * direction: a reason written that way does not count, so the finding stays visible.
     *
     * ## Why a concatenation of literals IS read, when a constant is not
     *
     * The two used to be refused together, on one sentence about evaluating project code. That
     * sentence is true of a constant and false of `'a ' . 'b'`, which is finished text sitting in
     * the parse tree with nothing left to resolve.
     *
     * The difference was not academic. A reason worth writing is often a sentence, a sentence does
     * not fit a line, and joining the halves with `.` is how PHP wraps one — so the most careful
     * annotation in a file was the one that silently did not count. Measured in a consuming project
     * before this changed: eighteen attributes in a tree, all of them looking like enforcement, and
     * the ones spanning two lines answering nothing.
     *
     * A constant anywhere in the expression still refuses the whole of it, which keeps the original
     * decision exactly where it was made.
     *
     * Whitespace is refused in every mode. Beyond that the mode decides: under
     * {@see AnalysePolicy::Strict} a configured placeholder — `todo`, `tbd`, whatever the project
     * lists — is not a reason either. Under `documented` it is, on purpose: a team mid-adoption is
     * better served by an annotation it can grep for than by a rule it switched off.
     */
    private function hasRealReason(Attribute $attribute): bool
    {
        foreach ($attribute->args as $index => $argument) {
            $isReason = $argument->name?->toString() === 'reason' || ($argument->name === null && $index === 0);

            if (! $isReason) {
                continue;
            }

            $reason = $this->literalText($argument->value);

            return $reason !== null && $this->config->accepts($reason);
        }

        return false;
    }

    /**
     * The text an expression carries in the SOURCE, or null when reading it would take more than
     * the parse tree.
     *
     * Recursive over `.` so a reason wrapped across three lines reads the same as one written on
     * one. Anything else — a constant, a variable, a call, an interpolated string — answers null,
     * and null is refusal rather than an empty reason: the finding stays.
     */
    private function literalText(Expr $expression): ?string
    {
        if ($expression instanceof String_) {
            return $expression->value;
        }

        if (! $expression instanceof Concat) {
            return null;
        }

        $left = $this->literalText($expression->left);
        $right = $this->literalText($expression->right);

        return $left === null || $right === null ? null : $left.$right;
    }
}
