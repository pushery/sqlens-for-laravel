<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Facade;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\Eval_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\ShellExec;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;

/**
 * Turns a call node into the thing it actually calls.
 *
 * A migration can reach the same facade in several spellings — imported
 * (`use Illuminate\Support\Facades\Http; Http::get()`), aliased
 * (`use ... as Client; Client::get()`), fully qualified
 * (`\Illuminate\Support\Facades\Http::get()`), or through Laravel's root alias
 * (`\Http::get()`). A catalog matched against the written text would catch one
 * of those and miss three, and the one it missed is the one someone ships.
 *
 * Imports are resolved by the parser's own name resolution; this class adds the
 * root-alias map on top and, deliberately, resolves targets OUTSIDE `Illuminate\*`
 * too — project classes, traits and helper functions. A side effect reached
 * through the application's own code is the most common way around a facade
 * catalog, and the detector for it needs the resolved target to work with.
 */
final readonly class NameResolver
{
    /** The helpers that resolve their first argument out of the container. */
    private const array CONTAINER_HELPERS = ['app', 'resolve'];

    /** The container's own methods that resolve their first argument. */
    private const array CONTAINER_METHODS = ['make', 'makeWith', 'get'];

    /**
     * The classes whose `getInstance()` is the container.
     *
     * The application by NAME: `Illuminate\Foundation` ships only inside laravel/framework, which
     * this package does not require, and a name is all a reading of a migration needs.
     */
    private const array CONTAINER_CLASSES = [Container::class, 'Illuminate\Foundation\Application'];

    /**
     * Laravel's root class aliases, for `\Http::get()` written without an import — read from the
     * INSTALLED framework rather than copied into a list here.
     *
     * It used to be a hand-written map of "the surfaces a migration might plausibly touch", and it
     * had drifted from Laravel 13 in both directions: `Process` and `RateLimiter` were missing while
     * both are in the side-effect catalog, so a migration writing `\Process::run(…)` without an
     * import resolved to nothing and the catalog never saw it — the pre-scan was blind on two
     * surfaces it claims to watch. And `Redis` was listed although Laravel 13 aliases no such name.
     *
     * Neither could be caught by a test, because a hand-written map is self-consistent by
     * construction: it agrees with the tests written beside it and with nothing else.
     *
     * Deriving it means the resolver answers what the framework answers. Judging which of those
     * surfaces MATTERS is a separate job, and it belongs to the catalog: the resolver turns a name
     * into a class, the catalog decides whether that class is a side effect. Splitting it that way
     * is also why taking all 47 aliases rather than a curated 18 costs nothing — an alias nobody
     * cataloged resolves and is then ignored.
     *
     * @return array<string, string> alias name => fully-qualified class
     */
    public static function frameworkAliases(): array
    {
        /** @var array<string, string> $aliases */
        $aliases = Facade::defaultAliases()->toArray();

        return $aliases;
    }

    /** @var array<string, string> */
    private array $aliases;

    /**
     * @param  array<string, string>|null  $aliases  alias name => fully-qualified class; null takes
     *                                               the installed framework's own map
     */
    public function __construct(?array $aliases = null)
    {
        $this->aliases = $aliases ?? self::frameworkAliases();
    }

    /**
     * Resolve any supported call node; anything else is explicitly dynamic.
     *
     * Four forms run code without being a call node, and each resolves to what it runs. Backticks
     * are `shell_exec()` in another spelling, so they resolve to that function and meet its
     * catalog entry. `include`, `require` and `eval()` run code this file does not contain, which
     * no catalog can judge, so they resolve as dynamic. `new Foo` runs Foo's constructor.
     */
    public function resolve(Node $node): CallTarget
    {
        $target = match (true) {
            $node instanceof StaticCall => $this->resolveStaticCall($node),
            $node instanceof MethodCall => $this->resolveMethodCall($node),
            $node instanceof FuncCall => $this->resolveFuncCall($node),
            $node instanceof New_ => $this->resolveNew($node),
            $node instanceof ShellExec => CallTarget::backticks(),
            $node instanceof Include_ => CallTarget::dynamic($this->includeForm($node).' of another file'),
            $node instanceof Eval_ => CallTarget::dynamic('an eval() of code built at run time'),
            default => CallTarget::dynamic('an unsupported call form'),
        };

        $resolution = $this->containerResolution($node);

        return $resolution === null ? $target : $target->resolvingFromContainer($resolution[0], $resolution[1]);
    }

    /**
     * The key a call resolves out of the container, with the call as written, or null.
     *
     * A migration reaches the cache as `Cache::forget()`, and just as well as `app('cache')->forget()`.
     * A catalog that knew only the facade saw the first and ran the second for real under pretend.
     * Five spellings hand the container a key, and a LITERAL key names what comes back as exactly as
     * a facade name does:
     *
     *  - `app('cache')` and `resolve('cache')`, the helpers;
     *  - `app()->make('cache')`, `->makeWith(…)` and `->get(…)`, the container's own methods;
     *  - the same on `Container::getInstance()` or `Application::getInstance()`;
     *  - `App::make('cache')` and its siblings, through the App facade.
     *
     * A key written as `Foo::class` is the class it names. A key computed at run time names nothing
     * a reading can know, and the call stays exactly what it was.
     *
     * @return array{string, string}|null the key, and the call as it reads with it
     */
    private function containerResolution(Node $node): ?array
    {
        if ($node instanceof FuncCall) {
            $helper = $node->name instanceof Name ? $this->nameOf($node->name) : null;
            $key = $helper !== null && in_array($helper, self::CONTAINER_HELPERS, true) ? $this->containerKeyIn($node->args) : null;

            return $key === null ? null : [$key, sprintf("%s('%s')", $helper, $key)];
        }

        if ($node instanceof MethodCall) {
            $method = $this->methodName($node->name);
            $container = $method !== null && in_array($method, self::CONTAINER_METHODS, true) ? $this->containerSpelling($node->var) : null;
            $key = $container === null ? null : $this->containerKeyIn($node->args);

            return $key === null ? null : [$key, sprintf("%s->%s('%s')", $container, $method, $key)];
        }

        if ($node instanceof StaticCall && $node->class instanceof Name) {
            $method = $this->methodName($node->name);
            $key = $method !== null && in_array($method, self::CONTAINER_METHODS, true) && $this->classFor($node->class) === App::class
                ? $this->containerKeyIn($node->args)
                : null;

            return $key === null ? null : [$key, sprintf("App::%s('%s')", $method, $key)];
        }

        return null;
    }

    /**
     * How a receiver reads when it is the container itself — `app()` without an argument, or the
     * container's `getInstance()` — and null for any other receiver.
     */
    private function containerSpelling(Expr $receiver): ?string
    {
        if ($receiver instanceof FuncCall && $receiver->name instanceof Name && $receiver->args === [] && $this->nameOf($receiver->name) === 'app') {
            return 'app()';
        }

        if ($receiver instanceof StaticCall && $receiver->class instanceof Name && $this->methodName($receiver->name) === 'getInstance') {
            $class = $this->classFor($receiver->class);

            return in_array($class, self::CONTAINER_CLASSES, true) ? substr((string) strrchr('\\'.$class, '\\'), 1).'::getInstance()' : null;
        }

        return null;
    }

    /**
     * The literal key in a call's first argument: a string, or the class a `Foo::class` names.
     *
     * Typed as nodes, because the parser's argument list has grown placeholder kinds across
     * versions, and only a plain positional `Arg` can carry a key.
     *
     * @param  array<Node>  $arguments
     */
    private function containerKeyIn(array $arguments): ?string
    {
        $first = $arguments[0] ?? null;

        if (! $first instanceof Arg || $first->unpack || $first->name instanceof Identifier) {
            return null;
        }

        $value = $first->value;

        if ($value instanceof String_) {
            return $value->value === '' ? null : ltrim($value->value, '\\');
        }

        return $value instanceof ClassConstFetch && $value->class instanceof Name && $this->methodName($value->name) === 'class'
            ? $this->nameOf($value->class)
            : null;
    }

    /**
     * `new Foo(...)` — the constructor of a named class, or of one only known at run time, which is
     * as unresolvable as a static call on a variable class name.
     */
    private function resolveNew(New_ $node): CallTarget
    {
        return $node->class instanceof Name
            ? CallTarget::construction($this->classFor($node->class))
            : CallTarget::dynamic('an object of a class named at run time');
    }

    /** The keyword an include was written with, with its article. */
    private function includeForm(Include_ $node): string
    {
        return match ($node->type) {
            Include_::TYPE_INCLUDE_ONCE => 'an include_once',
            Include_::TYPE_REQUIRE => 'a require',
            Include_::TYPE_REQUIRE_ONCE => 'a require_once',
            default => 'an include',
        };
    }

    /** `Foo::bar()` — resolved through imports, then through the alias map. */
    private function resolveStaticCall(StaticCall $node): CallTarget
    {
        $method = $this->methodName($node->name);
        if ($method === null) {
            return CallTarget::dynamic('a static call with a variable method name');
        }

        if (! $node->class instanceof Name) {
            return CallTarget::dynamic('a static call on a variable class name');
        }

        return CallTarget::staticCall($this->classFor($node->class), $method);
    }

    /**
     * `$x->bar()` — the method always resolves; the receiver only when it is a
     * direct `new Foo`. A call on a variable keeps its method name and a null
     * class, which is enough for a detector to decide it needs a closer look.
     */
    private function resolveMethodCall(MethodCall $node): CallTarget
    {
        $method = $this->methodName($node->name);
        if ($method === null) {
            return CallTarget::dynamic('a method call with a variable method name');
        }

        $class = $node->var instanceof New_ && $node->var->class instanceof Name
            ? $this->classFor($node->var->class)
            : null;

        return CallTarget::instanceCall($class, $method);
    }

    /**
     * A free function call. `call_user_func` and friends are reported as dynamic
     * BY NAME rather than resolved, because what they actually invoke is an
     * argument — exactly the indirection a catalog cannot follow.
     */
    private function resolveFuncCall(FuncCall $node): CallTarget
    {
        if (! $node->name instanceof Name) {
            return CallTarget::dynamic('a function call through a variable');
        }

        $name = $this->nameOf($node->name);

        if (in_array($name, ['call_user_func', 'call_user_func_array'], true)) {
            return CallTarget::dynamic('a call through '.$name.'()');
        }

        return CallTarget::function($name);
    }

    /**
     * The fully-qualified class a name node points at.
     *
     * The parser's name resolution has already applied the file's imports, so an
     * unqualified single-segment name that survives here is a root-level name —
     * which is where Laravel's aliases live.
     */
    private function classFor(Name $name): string
    {
        $resolved = $this->nameOf($name);

        return $this->aliases[$resolved] ?? $resolved;
    }

    private function nameOf(Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ltrim($resolved instanceof Name ? $resolved->toString() : $name->toString(), '\\');
    }

    /** The literal method name, or null when it is computed at runtime. */
    private function methodName(Identifier|Expr $name): ?string
    {
        return $name instanceof Identifier ? $name->toString() : null;
    }
}
