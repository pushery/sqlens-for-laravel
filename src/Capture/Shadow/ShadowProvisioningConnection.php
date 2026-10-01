<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Contracts\Config\Repository;

/**
 * The connection a shadow run creates and drops its throwaway databases through, which is not
 * always the connection the run examines.
 *
 * `capture.shadow.direct_connection` comes first, then `capture.shadow.connection`, then the run's
 * own connection. The shipped config describes `connection` as the place the shadow databases are
 * built, and the shadow-mode page tells a project to point it at a dedicated CREATEDB role, the
 * pattern Prisma calls a `shadowDatabaseUrl`. `direct_connection` wins when both are named, and that
 * order is mechanical rather than a preference: template operations and CREATE DATABASE break behind
 * a transaction pooler, so the connection that provably bypasses one has to be the link they run on.
 * A project that names only `connection` gets it; a project that names both has already said which
 * of the two must not be pooled.
 *
 * Two callers read this, and they are why it is one method. The factory builds the provisioner, the
 * maintenance link and the orphan sweep on the connection it names, and the clearance asks the
 * production detector about the same connection. Two copies of the order could drift, and the guard
 * would then judge one server while the provisioner creates and drops on another.
 */
final readonly class ShadowProvisioningConnection
{
    /** The name of the connection the throwaway databases are built on, for a run on $runConnection. */
    public static function for(Repository $config, string $runConnection): string
    {
        $direct = $config->get('sqlens.capture.shadow.direct_connection');
        $shadow = $config->get('sqlens.capture.shadow.connection');

        return match (true) {
            is_string($direct) && $direct !== '' => $direct,
            is_string($shadow) && $shadow !== '' => $shadow,
            default => $runConnection,
        };
    }
}
