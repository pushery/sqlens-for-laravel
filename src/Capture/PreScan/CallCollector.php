<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\Eval_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\Match_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\ShellExec;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Throw_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\MatchArm;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Case_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Do_;
use PhpParser\Node\Stmt\ElseIf_;
use PhpParser\Node\Stmt\For_;
use PhpParser\Node\Stmt\Foreach_;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Stmt\Switch_;
use PhpParser\Node\Stmt\While_;
use PhpParser\NodeFinder;
use PhpParser\NodeVisitorAbstract;

/**
 * Walks a parsed migration once and records every call it makes — resolved, with
 * the named method it sits in, and with its control-flow context.
 *
 * A call is anything that runs code: a function, method or static call, and four
 * forms that are no call node and run code all the same. `new Foo` runs Foo's
 * constructor, backticks run a shell command, and `include`, `require` and `eval()`
 * run code from outside the file. Left out, each of them was a way past every
 * detector. Two `new` forms stay out because they run nothing the pre-scan cannot
 * read: an anonymous class is written out in this file, and so is the migration's
 * own, reached as `self`, `static` or `parent`. An object built to be thrown ends
 * the migration instead of doing its work, so it stays out as well.
 *
 * One traversal, one shared result. Every detector reads this list instead of
 * walking the tree again for its own pattern — the pre-scan runs in front of the
 * fast path, and a per-detector traversal would multiply its cost by the number
 * of patterns. Context lives here for the same reason: three detectors need to
 * know whether a call sits in a condition or a loop, and each computing it for
 * itself is three more traversals plus three chances to compute it differently.
 */
final class CallCollector extends NodeVisitorAbstract
{
    /** @var list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}> */
    private array $calls = [];

    /**
     * The enclosing named function-likes, innermost last.
     *
     * Closures and arrow functions are deliberately not pushed: `Schema::create('t',
     * function (Blueprint $table) { ... })` is code that runs as part of `up()`, and
     * reporting its scope as "a closure" would lose the only fact a detector needs —
     * which migration method reaches it.
     *
     * @var list<string>
     */
    private array $scopes = [];

    /**
     * Open control-flow regions, each with the node that owns it and the source
     * range it covers.
     *
     * The RANGE is what makes this correct with a single traversal. While the body
     * of `if (cond) { ... }` is being walked, the `If_` node is still open — so
     * membership in the condition cannot be read off the stack alone. Comparing the
     * call's source position against the condition's range answers it exactly.
     *
     * @var list<array{owner: int, kind: string, from: int, to: int, literal: bool}>
     */
    private array $regions = [];

    /**
     * The `new` expressions that are thrown, keyed by object id. A `throw` is entered before the
     * object it throws, so the mark is there when the `new` is reached.
     *
     * @var array<int, true>
     */
    private array $thrown = [];

    /**
     * Whether each open function-like is a named one, innermost last: true for a method or a
     * function, false for a closure or an arrow function. A `return` in a closure hands its value to
     * whoever calls the closure, and a variable assigned there is the closure's own, so neither says
     * anything about the named function-like around it.
     *
     * @var list<bool>
     */
    private array $named = [];

    /**
     * Open expressions whose value leaves the statement it stands in: the expression of a `return`,
     * and the right side of an assignment to a plain variable, each in a named function-like. `depth`
     * is the number of function-likes open where it stands, so a call inside a closure written in
     * such an expression is not taken for one whose value is handed on.
     *
     * @var list<array{owner: int, kind: string, from: int, to: int, depth: int, variable: string|null}>
     */
    private array $flows = [];

    /**
     * Where the value of each recorded call goes, by its index in `$calls`: the named function-like
     * whose `return` hands it back, and the variable an assignment puts it in.
     *
     * @var array<int, array{returnedFrom: string|null, assignedTo: string|null}>
     */
    private array $destinations = [];

    /**
     * The variables each named function-like reads in an expression that decides a branch, by scope,
     * with `''` for the top level of the file.
     *
     * @var array<string, array<string, true>>
     */
    private array $decidingReads = [];

    /**
     * The variables each named function-like reads in an expression it returns, by scope.
     *
     * @var array<string, array<string, true>>
     */
    private array $returnedReads = [];

    public function __construct(private readonly NameResolver $resolver) {}

    public function enterNode(Node $node): null
    {
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            $this->scopes[] = $node->name->toString();
            $this->named[] = true;
        }

        if ($node instanceof Closure || $node instanceof ArrowFunction) {
            $this->named[] = false;
        }

        foreach ($this->regionsOpenedBy($node) as $region) {
            $this->regions[] = $region;
        }

        $this->recordFlowsOpenedBy($node);

        if ($node instanceof Throw_ && $node->expr instanceof New_) {
            $this->thrown[spl_object_id($node->expr)] = true;
        }

        if ($node instanceof StaticCall
            || $node instanceof MethodCall
            || $node instanceof FuncCall
            || $node instanceof ShellExec
            || $node instanceof Include_
            || $node instanceof Eval_
            || ($node instanceof New_ && $this->runsAConstructor($node))) {
            $this->calls[] = [
                'node' => $node,
                'target' => $this->resolver->resolve($node),
                'line' => $node->getStartLine(),
                'scope' => $this->scopes === [] ? null : $this->scopes[count($this->scopes) - 1],
                'context' => $this->contextAt($node->getStartFilePos()),
            ];
            $this->destinations[count($this->calls) - 1] = $this->destinationAt($node->getStartFilePos());
        }

        return null;
    }

    public function leaveNode(Node $node): null
    {
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            array_pop($this->scopes);
        }

        if ($node instanceof ClassMethod || $node instanceof Function_ || $node instanceof Closure || $node instanceof ArrowFunction) {
            array_pop($this->named);
        }

        $owner = spl_object_id($node);

        $this->regions = array_values(array_filter(
            $this->regions,
            static fn (array $region): bool => $region['owner'] !== $owner,
        ));
        $this->flows = array_values(array_filter(
            $this->flows,
            static fn (array $flow): bool => $flow['owner'] !== $owner,
        ));

        return null;
    }

    /**
     * Count every call whose value reaches a branch the long way round as one that decides it.
     *
     * A predicate decides a branch where it stands in the deciding expression, and just as much where
     * it is assigned to a variable such an expression reads, or returned by a method whose call stands
     * in one: `if (! $exists)` after `$exists = Schema::hasTable('t')`, or `$this->constrains() ? … : …`
     * over a `constrains()` that returns `Schema::hasTable('t') && …`. A variable the method reads in
     * what it returns counts as well, and a method that returns another one's call passes the decision
     * on. Read as straight-line code, each of these was a way past every detector that asks whether a
     * call decides something, and under pretend it hides the DDL behind it.
     *
     * A value nothing decides on stays plain: a count that is only logged is still no branch.
     *
     * @param  array<Node>  $nodes
     */
    public function afterTraverse(array $nodes): null
    {
        $deciding = [];

        foreach ($this->calls as $index => $call) {
            if ($call['context']->insideCondition) {
                $deciding[$index] = true;
            }
        }

        do {
            $methods = [];

            foreach (array_keys($deciding) as $index) {
                $method = $this->ownMethodCalled($this->calls[$index]['node']);

                if ($method !== null) {
                    $methods[$method] = true;
                }
            }

            $grown = false;

            foreach ($this->calls as $index => $call) {
                if (isset($deciding[$index])) {
                    continue;
                }

                $scope = $call['scope'] ?? '';
                $destination = $this->destinations[$index] ?? ['returnedFrom' => null, 'assignedTo' => null];
                $variable = $destination['assignedTo'];
                $returnedFrom = $destination['returnedFrom'];

                $throughVariable = $variable !== null
                    && (isset($this->decidingReads[$scope][$variable]) || (isset($methods[$scope]) && isset($this->returnedReads[$scope][$variable])));
                $throughReturn = $returnedFrom !== null && isset($methods[$returnedFrom]);

                if ($throughVariable || $throughReturn) {
                    $deciding[$index] = true;
                    $grown = true;
                }
            }
        } while ($grown);

        // Rebuilt whole, so every call keeps the shape `calls()` promises and the list stays a list.
        $calls = [];

        foreach ($this->calls as $index => $call) {
            if (isset($deciding[$index]) && ! $call['context']->insideCondition) {
                $call['context'] = new CallContext(true, $call['context']->insideLoopBody, $call['context']->loopIterablesAreLiteral);
            }

            $calls[] = $call;
        }

        $this->calls = $calls;

        return null;
    }

    /** @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}> */
    public function calls(): array
    {
        return $this->calls;
    }

    /**
     * Record where a node hands a value on, and which variables a deciding or a returned expression
     * reads. Only in a named function-like: at the top level of the file the `return` hands back the
     * migration itself, and every method of it stands inside that expression.
     */
    private function recordFlowsOpenedBy(Node $node): void
    {
        if ($this->named === [] || ! $this->named[count($this->named) - 1]) {
            return;
        }

        $scope = $this->scopes === [] ? '' : $this->scopes[count($this->scopes) - 1];

        foreach ($this->conditionExpressions($node) as $expression) {
            foreach ($this->variablesIn($expression) as $variable) {
                $this->decidingReads[$scope][$variable] = true;
            }
        }

        if ($node instanceof Return_ && $node->expr instanceof Expr) {
            foreach ($this->variablesIn($node->expr) as $variable) {
                $this->returnedReads[$scope][$variable] = true;
            }

            $this->flows[] = ['owner' => spl_object_id($node), 'kind' => 'returned', 'from' => $node->expr->getStartFilePos(), 'to' => $node->expr->getEndFilePos(), 'depth' => count($this->named), 'variable' => null];
        }

        if ($node instanceof Assign && $node->var instanceof Variable && is_string($node->var->name)) {
            $this->flows[] = ['owner' => spl_object_id($node), 'kind' => 'assigned', 'from' => $node->expr->getStartFilePos(), 'to' => $node->expr->getEndFilePos(), 'depth' => count($this->named), 'variable' => $node->var->name];
        }
    }

    /**
     * Where the value of a call at the given position goes: the named function-like that returns it,
     * and the variable it is assigned to, each from an expression of the same function-like.
     *
     * @return array{returnedFrom: string|null, assignedTo: string|null}
     */
    private function destinationAt(int $position): array
    {
        $returnedFrom = null;
        $assignedTo = null;
        $depth = count($this->named);

        foreach ($this->flows as $flow) {
            if ($flow['depth'] !== $depth || $position < $flow['from'] || $position > $flow['to']) {
                continue;
            }

            if ($flow['kind'] === 'returned') {
                $returnedFrom = $this->scopes === [] ? '' : $this->scopes[count($this->scopes) - 1];

                continue;
            }

            $assignedTo = $flow['variable'];
        }

        return ['returnedFrom' => $returnedFrom, 'assignedTo' => $assignedTo];
    }

    /**
     * The names of the plain variables a node reads, `$this` aside.
     *
     * @return list<string>
     */
    private function variablesIn(Node $node): array
    {
        $names = [];

        foreach (new NodeFinder()->findInstanceOf($node, Variable::class) as $variable) {
            if (is_string($variable->name) && $variable->name !== 'this') {
                $names[] = $variable->name;
            }
        }

        return $names;
    }

    /**
     * The method of its own class or the function a call reaches by name: `$this->m()`, `self::m()`,
     * `static::m()` or `m()`. Null for anything else.
     */
    private function ownMethodCalled(Node $node): ?string
    {
        if ($node instanceof MethodCall && $node->var instanceof Variable && $node->var->name === 'this' && $node->name instanceof Identifier) {
            return $node->name->toString();
        }

        if ($node instanceof StaticCall && $node->class instanceof Name && in_array($node->class->toLowerString(), ['self', 'static'], true) && $node->name instanceof Identifier) {
            return $node->name->toString();
        }

        return $node instanceof FuncCall && $node->name instanceof Name ? $node->name->getLast() : null;
    }

    /** Whether a `new` runs a constructor this file does not hold, and is not built to be thrown. */
    private function runsAConstructor(New_ $node): bool
    {
        if ($node->class instanceof Class_ || isset($this->thrown[spl_object_id($node)])) {
            return false;
        }

        return ! $node->class instanceof Name || ! in_array($node->class->toLowerString(), ['self', 'static', 'parent'], true);
    }

    /**
     * The control-flow regions a node opens.
     *
     * Conditions are covered by the range of the deciding expression only — the
     * branch bodies are ordinary code. Loop bodies are covered whole, and a
     * `foreach` over a written-out array is marked literal: it runs the same
     * number of times with or without a database, so it is not the shape that
     * makes a backfill vanish under pretend.
     *
     * @return list<array{owner: int, kind: string, from: int, to: int, literal: bool}>
     */
    private function regionsOpenedBy(Node $node): array
    {
        $owner = spl_object_id($node);
        $regions = [];

        foreach ($this->conditionExpressions($node) as $expression) {
            $regions[] = [
                'owner' => $owner,
                'kind' => 'condition',
                'from' => $expression->getStartFilePos(),
                'to' => $expression->getEndFilePos(),
                'literal' => false,
            ];
        }

        if ($node instanceof Foreach_ || $node instanceof While_ || $node instanceof Do_ || $node instanceof For_) {
            $body = $node->stmts;

            if ($body !== []) {
                $regions[] = [
                    'owner' => $owner,
                    'kind' => 'loop_body',
                    'from' => $body[0]->getStartFilePos(),
                    'to' => $body[count($body) - 1]->getEndFilePos(),
                    'literal' => $node instanceof Foreach_ && self::isLiteralIterable($node->expr),
                ];
            }
        }

        return $regions;
    }

    /**
     * The expressions whose value decides a branch. `match` contributes both its
     * subject and every arm's conditions — a predicate written in an arm decides
     * just as much as one written in an `if`.
     *
     * @return list<Node>
     */
    private function conditionExpressions(Node $node): array
    {
        return match (true) {
            $node instanceof If_,
            $node instanceof ElseIf_,
            $node instanceof While_,
            $node instanceof Do_,
            $node instanceof Ternary,
            $node instanceof Switch_,
            $node instanceof Match_ => [$node->cond],
            $node instanceof Case_ => $node->cond instanceof Expr ? [$node->cond] : [],
            $node instanceof MatchArm => $node->conds ?? [],
            default => [],
        };
    }

    /** The control-flow context of a call at the given source position. */
    private function contextAt(int $position): CallContext
    {
        $insideCondition = false;
        $insideLoopBody = false;
        $literal = true;

        foreach ($this->regions as $region) {
            if ($position < $region['from']) {
                continue;
            }
            if ($position > $region['to']) {
                continue;
            }
            if ($region['kind'] === 'condition') {
                $insideCondition = true;

                continue;
            }

            $insideLoopBody = true;
            $literal = $literal && $region['literal'];
        }

        return new CallContext($insideCondition, $insideLoopBody, $insideLoopBody && $literal);
    }

    /**
     * Whether a `foreach` iterates something whose length cannot depend on a
     * database — an array literal, a constant, or an index into either.
     *
     * A constant qualifies because it is fixed before the program runs: whatever
     * it holds, it holds the same on an empty database and a full one. Anything
     * else (a variable, a method call, a property) may be a query result, and the
     * pre-scan does not guess.
     */
    private static function isLiteralIterable(Node $expression): bool
    {
        return $expression instanceof Array_
            || $expression instanceof ClassConstFetch
            || $expression instanceof ConstFetch
            || ($expression instanceof ArrayDimFetch && self::isLiteralIterable($expression->var));
    }
}
