<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Http\Request;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Type\ObjectType;

/**
 * Did this expression come out of the HTTP request?
 *
 * ## Why the question is asked at all, when the classifier already answers a bigger one
 *
 * {@see ParameterizationAnalyzer} says whether an expression's value is known at analysis time. For
 * a raw-SQL fragment that is the whole story — an unknown value belongs in a binding whatever its
 * origin. For an IDENTIFIER it is not: a column name cannot be bound, so "unknown" is the normal
 * state of any application that lets a user sort a table, and reporting all of them would make the
 * rule the loudest thing in the package.
 *
 * So the identifier rule needs a second, narrower signal: not merely *unknown*, but *unknown and
 * arriving from outside*. This class is that signal, and it is deliberately conservative — it
 * answers yes only where the request is visible in the expression itself.
 *
 * ## What "visible" means, and the measurement behind it
 *
 * Measured against `laravel/framework` v13.23.0 with Larastan loaded:
 *
 *     $request->input('sort')                          →  mixed
 *     request()->input('sort')                         →  mixed
 *     if (in_array($sort, ['name','created_at'], true) →  'created_at'|'name'
 *     self::SORTABLE[$key] ?? 'created_at'             →  'created_at'|'customer_name'
 *     match ((string) $request->input('sort')) { … }   →  'created_at'|'customer_name'
 *
 * The last three are the shapes a team uses as an allowlist, and every one of them narrows to a
 * union of constant strings. That is why the noise control needs no code of its own: the classifier
 * already reports them as fully known, and this class is only consulted for what it does not.
 *
 * ## The honest limit
 *
 * One expression, one scope. A request value assigned to a property in a constructor and read in
 * another method is invisible here — that is not taint analysis, and this package does not do taint
 * analysis. The rule reads the absence of a visible origin as *undetermined with a named reason*
 * rather than as a pass, which is the only reading that does not quietly certify the case it cannot
 * see.
 */
final readonly class RequestOrigin
{
    /**
     * Methods on a `Request` that hand back something the caller typed.
     *
     * `all()` and `validated()` are here even though a project may consider validation a defense:
     * validation checks a value's SHAPE, and an identifier's danger is not its shape. A validated
     * `sort=name` and a validated `sort=1;DROP` differ only in a rule somebody wrote, which this
     * class cannot see and will not assume.
     *
     * @var list<string>
     */
    private const array REQUEST_READERS = [
        'all', 'boolean', 'date', 'enum', 'float', 'get', 'input', 'integer', 'json',
        'only', 'post', 'query', 'safe', 'str', 'string', 'validated',
    ];

    /**
     * Global helpers that produce a request.
     *
     * `request()` is the one people write; `old()` reads flashed input, which is request data that
     * survived a redirect and is exactly as user-typed as the original.
     *
     * @var list<string>
     */
    private const array REQUEST_HELPERS = ['request', 'old'];

    /**
     * Does the request appear anywhere inside this expression?
     *
     * Recursive on purpose, because the value almost never IS the call: `(string) $request->input()`,
     * `$request->input('sort') ?? 'id'`, `trim($request->query('sort'))` are the ordinary shapes, and
     * a check that only matched the bare call would be silent on all of them.
     */
    public function reaches(Expr $expression, Scope $scope): bool
    {
        if ($this->isRequestRead($expression, $scope) || $this->isRequestHelper($expression)) {
            return true;
        }

        foreach ($expression->getSubNodeNames() as $name) {
            /** @var mixed $child */
            $child = $expression->{$name};

            foreach (is_array($child) ? $child : [$child] as $item) {
                // An argument wraps its expression, so both shapes are unwrapped here rather than in
                // two branches: `(string) $request->input()` nests an Expr directly, a call's args
                // nest `Arg` objects that carry one.
                $inner = match (true) {
                    $item instanceof Expr => $item,
                    $item instanceof Arg => $item->value,
                    default => null,
                };

                if ($inner instanceof Expr && $this->reaches($inner, $scope)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * A read off a `Request` object — `$request->input(…)`, or `$request->sort` as a magic property.
     *
     * The RECEIVER's type decides, not the method name, so a repository with an `input()` method is
     * not mistaken for the request. A property fetch counts because `Request` resolves unknown
     * properties to input data, which is the shortest way to write the dangerous thing.
     */
    private function isRequestRead(Expr $expression, Scope $scope): bool
    {
        if ($expression instanceof StaticCall) {
            return $expression->class instanceof Name
                && $scope->resolveName($expression->class) === \Illuminate\Support\Facades\Request::class;
        }

        if ($expression instanceof PropertyFetch) {
            return $this->isRequest($expression->var, $scope);
        }

        if (! $expression instanceof MethodCall || ! $expression->name instanceof Identifier) {
            return false;
        }

        return in_array($expression->name->toString(), self::REQUEST_READERS, true)
            && $this->isRequest($expression->var, $scope);
    }

    /** The `request()` / `old()` helpers, by name. */
    private function isRequestHelper(Expr $expression): bool
    {
        return $expression instanceof FuncCall
            && $expression->name instanceof Name
            && in_array(strtolower($expression->name->toString()), self::REQUEST_HELPERS, true);
    }

    /** Is this expression a `Request`? Asked of the resolved type, so a subclass answers yes. */
    private function isRequest(Expr $expression, Scope $scope): bool
    {
        return new ObjectType(Request::class)->isSuperTypeOf($scope->getType($expression))->yes();
    }
}
