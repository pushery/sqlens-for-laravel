<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Attribute;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Attributes\SqlensIgnore;

/**
 * Which classes and methods carry a reasoned `#[RawSql]`.
 *
 * ## Justification, not suppression — and this file got that wrong once
 *
 * It first read {@see SqlensIgnore}, on the reasoning that the package must have exactly one
 * annotation and a second would be a duplicate. The reasoning was sound; the conclusion was not.
 * The two are not two spellings of one idea, they are two different statements:
 *
 * - `#[SqlensIgnore]` says *"I know, do not tell me."* The finding IS produced and then hidden, and
 *   it appears in the report as `suppressed_by` — visible, counted, attributable.
 * - `#[RawSql]` says *"the rule's question is answered."* No finding exists, because the reason it
 *   asks for is present.
 *
 * Read through one channel, a report can no longer tell "somebody looked at this and accepted it"
 * from "this was never a finding" — and that distinction is why `suppressed_by` exists at all.
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
 *
 * ## Methods as well as classes
 *
 * Reached through the class node rather than by a second collector: PHPStan's registry does not walk
 * subclasses, so one collector per node shape is the rule — but a class node carries its own
 * statements, and one traversal therefore sees both levels.
 *
 * @implements Collector<Class_, array{names: list<string>}|null>
 */
final readonly class JustificationCollector implements Collector
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

    public function getNodeType(): string
    {
        return Class_::class;
    }

    /**
     * Every name in this class that carries a reasoned `#[RawSql]`.
     *
     * A list rather than one entry, because `processNode` runs once per node and a class can hold
     * several annotated methods. Returning the first would justify one call site and leave the
     * others reporting — which reads as an inconsistent rule rather than as a missing entry.
     *
     * @return array{names: list<string>}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if ($node->namespacedName === null) {
            return null;
        }

        $class = $node->namespacedName->toString();
        $names = [];

        // A class-level annotation covers every call in the class; a method-level one covers only
        // that method. Both are recorded under the name a call site reports itself as, so the rule
        // downstream joins on equality rather than on a prefix.
        if ($this->isReasoned($node->attrGroups, $scope)) {
            $names[] = $class;
        }

        foreach ($node->stmts as $statement) {
            if ($statement instanceof ClassMethod && $this->isReasoned($statement->attrGroups, $scope)) {
                $names[] = $class.'::'.$statement->name->toString();
            }
        }

        // An unannotated class is the overwhelming majority, and one entry per class in a codebase
        // would make the rule's join proportional to the whole project for no gain.
        return $names === [] ? null : ['names' => $names];
    }

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
    private function isReasoned(array $groups, Scope $scope): bool
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
     * Only a literal string is read. A constant, a variable or a concatenation is not resolved, and
     * that is deliberate rather than lazy: resolving it would mean evaluating project code during
     * analysis. The consequence lands in the safe direction — a reason written that way does not
     * count, so the finding stays visible.
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

            if ($isReason && $argument->value instanceof String_) {
                return $this->config->accepts($argument->value->value);
            }
        }

        return false;
    }
}
