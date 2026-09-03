<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Pushery\SQLens\Lint\ShadowClearance;

/**
 * The application's answer to {@see ShadowClearance} — everything the production guard needs,
 * gathered at the boundary and handed over as one decision.
 *
 * Extracted from the lint command rather than invented: the four values below are the ones it read,
 * unchanged. What is new is only that a second caller can ask the same question and get the same
 * answer, instead of gathering them again.
 *
 * It resolves the connection NAME the same way the run does — the argument when one was given, the
 * application's default otherwise — because the guard has to judge the connection the run actually
 * addresses. A guard that judged the default while the run addressed a named production connection
 * would be a guard in name only.
 *
 * Nothing here decides. {@see ProductionGuard} decides, and it is the only thing that does; this
 * class knows where the inputs live.
 */
final readonly class ApplicationShadowClearance implements ShadowClearance
{
    public function __construct(
        private Application $app,
        private Repository $config,
        private ProductionGuard $guard = new ProductionGuard,
    ) {}

    public function decide(?string $connection, bool $force, bool $interactive, bool $confirmed): GuardDecision
    {
        $configuredDefault = $this->config->get('database.default');
        $name = $connection !== null && $connection !== ''
            ? $connection
            : (is_string($configuredDefault) ? $configuredDefault : '');

        $allowed = $this->config->get('sqlens.capture.shadow.allowed_environments');

        return $this->guard->evaluate(
            (string) $this->app->environment(),
            // Filtered to strings rather than trusted: it comes from a file the project edits, and a
            // non-string entry silently matching nothing would widen the check in the direction that
            // costs a database.
            is_array($allowed) ? array_values(array_filter($allowed, is_string(...))) : [],
            new ProductionConnectionDetector($this->config)->isProduction($name),
            $force,
            $interactive,
            $confirmed,
        );
    }
}
