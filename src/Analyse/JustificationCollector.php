<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
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
 * Reached through the class node rather than by a second collector: a class node carries its own
 * statements, so one traversal sees both levels.
 *
 * ⚠️ THIS PARAGRAPH USED TO GIVE A REASON THAT IS NOT TRUE — *"PHPStan's registry does not walk
 * subclasses, so one collector per node shape is the rule"*. Measured against the installed
 * version: `PHPStan\Collectors\Registry::getCollectors()` resolves through `class_parents` plus
 * `class_implements` of the node's actual class, so a collector may declare an interface and be
 * reached for every node implementing it. The sentence was load-bearing in the wrong direction — it
 * argued that reaching a free function or a closure would cost a collector per shape, and the two
 * shapes stayed unreachable while `#[RawSql]` went on declaring `TARGET_FUNCTION`.
 * {@see JustificationSpanCollector} is the one registration that reaches all of them.
 *
 * ## What this collector deliberately does NOT reach
 *
 * A free function and a closure. Neither has a name a call site inside it reports — outside a class
 * the call site's own scope name is `null` — so a name join has nothing to compare. They are covered
 * by POSITION instead, in the span collector beside this one.
 *
 * @implements Collector<Class_, array{names: list<string>, lines: list<int>, interpolationNames: list<string>}|null>
 */
final readonly class JustificationCollector implements Collector
{
    /**
     * The one unit that decides what counts as a reason — the run's policy lives inside it.
     *
     * Read at COLLECTION time rather than in the rule, and the placement is the whole design: a
     * reason the mode refuses is simply not collected, so the rule downstream needs no second notion
     * of "reasoned" and cannot drift from this one. It is a shared unit rather than a method here
     * because {@see JustificationSpanCollector} asks the identical question, and two answers to it
     * would let an annotation justify a call site through one channel and not the other.
     */
    public function __construct(private RawSqlReason $reason = new RawSqlReason) {}

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
     * Each name carries the LINE its annotation sits on, in a parallel list. Nothing needs it to
     * justify a call site — a name join has no use for a position — but {@see StaleRawSqlReasonRule}
     * reports the annotation itself, and a finding has to point somewhere. Parallel rather than a
     * map, because a class and a method of the same name are two entries and a map would keep one.
     *
     * `interpolationNames` is the SECOND channel and is kept apart from the first on purpose: an
     * annotation answering only "why raw SQL" must not clear an injection finding. See
     * {@see RawSql} for why the two questions are separate arguments.
     *
     * @return array{names: list<string>, lines: list<int>, interpolationNames: list<string>}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // `namespacedName` FIRST, and the order is load-bearing: on a declared class `name` is the
        // SHORT name while only `namespacedName` carries the fully-qualified one a call site
        // reports. `name` is the fallback, and the case it exists for is the anonymous class.
        //
        // ## Why an anonymous class needs a fallback at all
        //
        // PHPStan reflects `new class extends Migration { … }` before it walks the body, and that
        // step writes a synthetic identifier onto the node while explicitly nulling
        // `namespacedName` (`BetterReflectionProvider::getAnonymousClassReflection()`). The
        // identifier it writes — `AnonymousClass<hash>` — is exactly the string
        // `ClassReflection::getName()` answers for code INSIDE that class, which is what every
        // call-site collector records as its scope. So the two sides do join; this collector simply
        // returned before it looked.
        //
        // The consequence was not marginal. Every Laravel migration since Laravel 9 is
        // `return new class extends Migration`, and migrations are where raw DDL lives — so the
        // rule's own escape hatch was shut in the one place the rule fires most, leaving
        // `policy: off` or an `exclude_paths` entry as the only answers. Both silence more than the
        // finding, which is the outcome this package's own documentation warns about.
        //
        // It is NOT the display name. `class@anonymous/path/to/file.php:12` is what PHPStan builds
        // for messages; joining on that would match a string neither side ever produces.
        $class = $node->namespacedName?->toString() ?? $node->name?->toString();
        $names = [];
        $lines = [];
        $interpolationNames = [];

        // A class-level annotation covers every call in the class; a method-level one covers only
        // that method. Both are recorded under the name a call site reports itself as, so the rule
        // downstream joins on equality rather than on a prefix.
        if ($class !== null && $this->reason->isPresentIn($node->attrGroups, $scope)) {
            $names[] = $class;
            $lines[] = $node->getStartLine();
        }

        if ($class !== null && $this->reason->justifiesInterpolationIn($node->attrGroups, $scope)) {
            $interpolationNames[] = $class;
        }

        foreach ($class === null ? [] : $node->stmts as $statement) {
            if (! $statement instanceof ClassMethod) {
                continue;
            }

            if ($this->reason->isPresentIn($statement->attrGroups, $scope)) {
                $names[] = $class.'::'.$statement->name->toString();
                $lines[] = $statement->getStartLine();
            }

            if ($this->reason->justifiesInterpolationIn($statement->attrGroups, $scope)) {
                $interpolationNames[] = $class.'::'.$statement->name->toString();
            }
        }

        // An unannotated class is the overwhelming majority, and one entry per class in a codebase
        // would make the rule's join proportional to the whole project for no gain.
        return $names === [] && $interpolationNames === []
            ? null
            : ['names' => $names, 'lines' => $lines, 'interpolationNames' => $interpolationNames];
    }
}
