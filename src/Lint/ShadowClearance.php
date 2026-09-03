<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\Shadow\GuardDecision;

/**
 * Whether a database-creating run may proceed against a named connection.
 *
 * ## Why this contract exists at all
 *
 * The production guard evaluates plain inputs — an environment, an allowed list, whether the target
 * looks like production, and the three confirmation flags. Somebody has to GATHER those, and the
 * command did it privately. The moment a second caller needed the same decision, that private method
 * became a specification only one caller could read: a second gathering would be a second answer to
 * "which environments are allowed", free to drift, and drifting toward permissive is how a mode that
 * creates and drops databases ends up somewhere it may not be.
 *
 * So the gathering is here, once, and both callers are consumers of it. The agent layer's
 * architecture test lists this among the doors it may reach the engine through, for exactly that
 * reason: a tool can ASK for a verdict and can never compute one.
 *
 * ## Why the three confirmation flags stay separate
 *
 * They mean different things and the report says so. `--force` is a standing yes recorded in the run
 * header; an interactive run somebody confirmed is a yes given once and NOT recorded as force.
 * Collapsing them into one boolean would make a confirmed interactive run report `force: true`,
 * which describes a run nobody made — and the header exists so a decision can be reproduced.
 *
 * A caller that cannot be asked passes `interactive: false`, and then the only route to a yes is
 * `force`. That is deliberate: silence is never consent, least of all from something that has
 * nobody to ask.
 */
interface ShadowClearance
{
    /**
     * The guard's verdict for this connection.
     *
     * @param  string|null  $connection  the connection the run addresses; null means the application default
     * @param  bool  $force  the explicit standing yes — never overrides the allowed-environment check
     * @param  bool  $interactive  whether anybody COULD be asked
     * @param  bool  $confirmed  whether the person who was asked said yes
     */
    public function decide(?string $connection, bool $force, bool $interactive, bool $confirmed): GuardDecision;
}
