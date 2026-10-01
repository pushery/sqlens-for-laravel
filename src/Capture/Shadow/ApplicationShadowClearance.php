<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Lint\ShadowClearance;

/**
 * The application's answer to {@see ShadowClearance} — everything the production guard needs,
 * gathered at the boundary and handed over as one decision.
 *
 * Extracted from the lint command rather than invented: the four values below are the ones it read,
 * unchanged. What is new is only that a second caller can ask the same question and get the same
 * answer, instead of gathering them again.
 *
 * It resolves the connection NAME the same way the run does — the argument when one was given,
 * {@see DriverManager::defaultConnectionName()} otherwise — because the guard has to judge the
 * connection the run actually addresses. A guard that judged the default while the run addressed a
 * named production connection would be a guard in name only.
 *
 * That second half asks the resolver rather than reading `database.default`, which is not how a
 * run resolves: `sqlens.connection` comes first, and it is an ordinary documented key. With it set,
 * `database.default` would have the guard judge a database nothing is running against while the
 * provisioner creates on the other one. Asking the resolver rather than re-implementing it is the
 * only version of this that cannot drift.
 *
 * It asks about a second connection too: the one the throwaway databases are created and dropped
 * on. With `capture.shadow.connection` or `capture.shadow.direct_connection` set, that is not the
 * connection under examination, and it is the one a database-creating mode writes to. A guard that
 * judged only the examined connection would let a run create, replay into and drop databases on a
 * server it never looked at, the same mistake as judging the default one level down. The name comes
 * from {@see ShadowProvisioningConnection}, the resolver the provisioner is built from.
 *
 * Nothing here decides. {@see ProductionGuard} decides, and it is the only thing that does; this
 * class knows where the inputs live.
 */
final readonly class ApplicationShadowClearance implements ShadowClearance
{
    public function __construct(
        private Application $app,
        private Repository $config,
        private DriverManager $drivers,
        private ProductionGuard $guard = new ProductionGuard,
    ) {}

    public function decide(?string $connection, bool $force, bool $interactive, bool $confirmed): GuardDecision
    {
        $name = $connection !== null && $connection !== ''
            ? $connection
            : $this->drivers->defaultConnectionName();

        $allowed = $this->config->get('sqlens.capture.shadow.allowed_environments');
        $detector = new ProductionConnectionDetector($this->config);

        return $this->guard->evaluate(
            (string) $this->app->environment(),
            // Filtered to strings rather than trusted: it comes from a file the project edits, and a
            // non-string entry silently matching nothing would widen the check in the direction that
            // costs a database.
            is_array($allowed) ? array_values(array_filter($allowed, is_string(...))) : [],
            // Both connections the run reaches: the one it examines, and the one it creates and
            // drops its throwaway databases on. Without a shadow or direct connection configured
            // they are the same, and the second question repeats the first.
            $detector->isProduction($name)
                || $detector->isProduction(ShadowProvisioningConnection::for($this->config, $name)),
            $force,
            $interactive,
            $confirmed,
        );
    }
}
