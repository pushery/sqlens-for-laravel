<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Match_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\MatchArm;
use PhpParser\Node\Stmt\Case_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Do_;
use PhpParser\Node\Stmt\ElseIf_;
use PhpParser\Node\Stmt\For_;
use PhpParser\Node\Stmt\Foreach_;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Switch_;
use PhpParser\Node\Stmt\While_;
use PhpParser\NodeVisitorAbstract;

/**
 * Walks a parsed migration once and records every call it makes — resolved, with
 * the named method it sits in, and with its control-flow context.
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
     * The enclosing NAMED function-likes, innermost last.
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

    public function __construct(private readonly NameResolver $resolver) {}

    public function enterNode(Node $node): null
    {
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            $this->scopes[] = $node->name->toString();
        }

        foreach ($this->regionsOpenedBy($node) as $region) {
            $this->regions[] = $region;
        }

        if ($node instanceof StaticCall
            || $node instanceof MethodCall
            || $node instanceof FuncCall) {
            $this->calls[] = [
                'node' => $node,
                'target' => $this->resolver->resolve($node),
                'line' => $node->getStartLine(),
                'scope' => $this->scopes === [] ? null : $this->scopes[count($this->scopes) - 1],
                'context' => $this->contextAt($node->getStartFilePos()),
            ];
        }

        return null;
    }

    public function leaveNode(Node $node): null
    {
        if ($node instanceof ClassMethod || $node instanceof Function_) {
            array_pop($this->scopes);
        }

        $owner = spl_object_id($node);

        $this->regions = array_values(array_filter(
            $this->regions,
            static fn (array $region): bool => $region['owner'] !== $owner,
        ));

        return null;
    }

    /** @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}> */
    public function calls(): array
    {
        return $this->calls;
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
