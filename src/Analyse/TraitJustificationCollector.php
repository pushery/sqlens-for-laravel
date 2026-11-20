<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Stmt\ClassMethod;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Node\InTraitNode;
use PHPStan\Reflection\ClassReflection;
use Pushery\SQLens\Attributes\RawSql;

/**
 * Which methods a reasoned `#[RawSql]` covers where it stands on a trait, in each class that uses the trait.
 *
 * PHPStan reads a trait's methods once for every class that uses it, and a call site inside one
 * reports itself under that class: `App\Livewire\Orders::lockTheForm`, never under the trait. So a
 * trait's annotation is recorded under the names the call sites carry, once per using class, and
 * the name join of {@see JustificationCoverage} reads it like an annotation written in the class. One
 * on the declaration itself covers every method declared in the trait; one on a method covers that method.
 *
 * {@see JustificationCollector} cannot see it: it reads `Class_` nodes, and traits are nodes of their
 * own. This collector reads the node PHPStan emits for each class that uses a trait, which carries
 * the trait's declaration as written and the class it is read for.
 *
 * ## The trait's method, under each name the class gives it
 *
 * A class can give a trait's method a second name (`use Locks { lockTheForm as lockBeforeSaving; }`),
 * and PHPStan then reads its body under that name. A class can also declare a method of the same name
 * itself, or take it from another trait, and that method is not the trait's although it carries the
 * name: covering it would excuse code the annotation never spoke for. So a name is recorded only where
 * the class's method of that name IS the trait's method, judged by where it is written, file and
 * line, through PHPStan's static reflection, which loads nothing.
 *
 * Where a class replaces the method, PHPStan still reads the trait's body under that name, and a call
 * site in it is reported for that class. A finding there is the price of never excusing the class's
 * own method.
 *
 * ## Where a finding about the annotation points
 *
 * Each annotation carries the trait's own file and its line, and a label naming the trait, or the
 * trait's method, so {@see StaleRawSqlReasonRule} reports a stale reason where it is written, once,
 * however many classes use the trait.
 *
 * @implements Collector<InTraitNode, array{file: string, annotations: list<array{line: int, label: string, rawSql: bool, interpolation: bool, names: list<string>}>}|null>
 */
final readonly class TraitJustificationCollector implements Collector
{
    /**
     * The same unit {@see JustificationCollector} asks, so a trait's annotation counts exactly
     * where one on a class does, under the run's policy.
     */
    public function __construct(private RawSqlReason $reason = new RawSqlReason) {}

    public function getNodeType(): string
    {
        return InTraitNode::class;
    }

    /**
     * Every reasoned annotation of this trait, with the names it covers in the class it is read for.
     *
     * @return array{file: string, annotations: list<array{line: int, label: string, rawSql: bool, interpolation: bool, names: list<string>}>}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        $declaration = $node->getOriginalNode();
        $traitName = $node->getTraitReflection()->getName();
        $file = $node->getTraitReflection()->getNativeReflection()->getFileName();
        $class = $node->getImplementingClassReflection();
        $annotations = [];
        $everyMethod = [];

        foreach ($declaration->getMethods() as $method) {
            $names = $this->namesIn($class, $traitName, $file, $method);
            $everyMethod = [...$everyMethod, ...$names];
            $annotations[] = $this->annotation($method->attrGroups, $scope, $method->getStartLine(), $traitName.'::'.$method->name->toString(), $names);
        }

        // The trait's own annotation reaches every method it declares, as one on a class does.
        $annotations[] = $this->annotation($declaration->attrGroups, $scope, $declaration->getStartLine(), $traitName, $everyMethod);
        $annotations = array_values(array_filter($annotations));

        // Traits without a reasoned annotation are the overwhelming majority, as with classes.
        if ($annotations === []) {
            return null;
        }

        return ['file' => (string) $file, 'annotations' => $annotations];
    }

    /**
     * One annotation and the names it covers, or null where the attributes carry no reason this run
     * accepts for either question.
     *
     * @param  array<AttributeGroup>  $attrGroups
     * @param  list<string>  $names
     * @return array{line: int, label: string, rawSql: bool, interpolation: bool, names: list<string>}|null
     */
    private function annotation(array $attrGroups, Scope $scope, int $line, string $label, array $names): ?array
    {
        $rawSql = $this->reason->isPresentIn($attrGroups, $scope);
        $interpolation = $this->reason->justifiesInterpolationIn($attrGroups, $scope);

        if (! $rawSql && ! $interpolation) {
            return null;
        }

        return ['line' => $line, 'label' => $label, 'rawSql' => $rawSql, 'interpolation' => $interpolation, 'names' => $names];
    }

    /**
     * The names the trait's method goes by in the class, as a call site inside it reports itself: its
     * own name and each alias the class gives it, each only where the class's method of that name is
     * this one.
     *
     * The {@see RawSql} attribute reaches no further than that method, which is why a name the class
     * fills with a method of its own is left out.
     *
     * @return list<string>
     */
    private function namesIn(ClassReflection $class, string $trait, string|false $file, ClassMethod $method): array
    {
        $native = $class->getNativeReflection();
        $candidates = [$method->name->toString()];

        foreach ($native->getTraitAliases() as $alias => $original) {
            if (strcasecmp($original, $trait.'::'.$method->name->toString()) === 0) {
                $candidates[] = $alias;
            }
        }

        $names = [];

        foreach ($candidates as $candidate) {
            $resolved = $native->hasMethod($candidate) ? $native->getMethod($candidate) : null;

            if ($resolved?->getFileName() === $file && $resolved->getStartLine() === $method->getStartLine()) {
                $names[] = $class->getName().'::'.$candidate;
            }
        }

        return $names;
    }
}
