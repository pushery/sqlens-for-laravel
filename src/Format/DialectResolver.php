<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Illuminate\Contracts\Config\Repository;

/**
 * Which dialect a run formats for, from the connection it is pointed at.
 *
 * ## It answers with a VALUE and never with a driver
 *
 * The whole reason `src/Format/` can stay driver-neutral. Returning a driver object here would pull
 * the driver hierarchy into the formatter namespace, and the architecture test that keeps the two
 * apart would have to be weakened to allow it.
 *
 * ## An engine this package does not support is NAMED, not mapped onto its neighbor
 *
 * MariaDB arrives behind Laravel's `mysql` driver key and is a declared non-goal — the two share a
 * driver key and a wire protocol and not the semantics every MySQL rule here reasons about. Mapping
 * it onto `Dialect::Mysql` would format it with confidence for another product, which is exactly the
 * dishonesty the non-goal decision exists to prevent.
 */
final readonly class DialectResolver
{
    public function __construct(private Repository $config) {}

    /**
     * @param  string|null  $requested  an explicit dialect from a flag or from config, or null/auto
     */
    public function resolve(?string $requested = null): DialectResolution
    {
        if (! in_array($requested, [null, '', 'auto'], true)) {
            $named = Dialect::tryFrom($requested);

            // An explicit dialect short-circuits everything: the connection is never read, so a run
            // with `--dialect` touches no configuration beyond its own flag and needs no database at
            // all. That is the property the north-star rests on.
            return $named instanceof Dialect
                ? DialectResolution::of($named)
                : DialectResolution::unsupported($requested);
        }

        $connection = $this->config->get('sqlens.connection') ?? $this->config->get('database.default');

        if (! is_string($connection) || $connection === '') {
            return DialectResolution::unknown();
        }

        $driver = $this->config->get('database.connections.'.$connection.'.driver');

        if (! is_string($driver) || $driver === '') {
            return DialectResolution::unknown();
        }

        $dialect = Dialect::tryFrom($driver);

        return $dialect instanceof Dialect ? DialectResolution::of($dialect) : DialectResolution::unsupported($driver);
    }
}
