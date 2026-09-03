<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Illuminate\Support\Facades\Facade;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

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

    /** Resolve any supported call node; anything else is explicitly dynamic. */
    public function resolve(Node $node): CallTarget
    {
        return match (true) {
            $node instanceof StaticCall => $this->resolveStaticCall($node),
            $node instanceof MethodCall => $this->resolveMethodCall($node),
            $node instanceof FuncCall => $this->resolveFuncCall($node),
            default => CallTarget::dynamic('an unsupported call form'),
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
