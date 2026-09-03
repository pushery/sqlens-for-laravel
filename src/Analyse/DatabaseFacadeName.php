<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

/**
 * Does a static call's subject name Laravel's database facade?
 *
 * One question, asked by two collectors — {@see RawSqlCallCollector} for the statement sinks and
 * {@see RawSqlExpressionCollector} for `DB::raw()`. It lives here rather than in either of them
 * because the answer is subtle enough that a second copy would drift, and drift in this particular
 * check is invisible: both directions of the mistake are silent. A copy that grows narrower stops
 * reporting real raw SQL; one that grows wider reports a project's own class of the same name, and
 * the team mutes the rule.
 *
 * ## Why the NAME rather than the resolved type
 *
 * A facade's subject IS a name. `$scope->getType()` on it answers "the facade class", which is true
 * and useless for telling `DB::select()` apart from `Orders::select()`.
 */
final readonly class DatabaseFacadeName
{
    public function __construct(private ReflectionProvider $reflection) {}

    public function isDatabaseFacade(StaticCall $node, Scope $scope): bool
    {
        if (! $node->class instanceof Name) {
            return false;
        }

        $name = $scope->resolveName($node->class);

        if ($name === DB::class || $name === Connection::class) {
            return true;
        }

        // Laravel registers `DB` as a ROOT ALIAS in `config/app.php`, so `\DB::statement(…)` is
        // ordinary application code — and `resolveName()` answers the alias, `DB`, not the facade's
        // fully qualified name. The comparison above therefore misses every call written that way,
        // and the miss is SILENT: with Larastan loaded the alias resolves, PHPStan is content, and
        // an obvious interpolation in an UPDATE produces no finding from anybody.
        //
        // The repair that suggests itself — accept the bare name too — would report a project's OWN
        // class of that name, trading one silence for noise on ordinary code. Reflection answers the
        // question exactly instead: PHP's class aliasing is transparent to it, so the alias reflects
        // as the class it names while an unrelated `DB` reflects as itself. Measured on this tree:
        //
        //     written=\Illuminate\Support\Facades\DB  resolveName=Illuminate\…\DB  reflected=Illuminate\…\DB
        //     written=\DB                             resolveName=DB              reflected=Illuminate\…\DB
        //
        // Reached only when the cheap comparison already failed, so the ordinary path pays nothing.
        if (! $this->reflection->hasClass($name)) {
            return false;
        }

        $reflected = $this->reflection->getClass($name)->getName();

        return $reflected === DB::class || $reflected === Connection::class;
    }
}
