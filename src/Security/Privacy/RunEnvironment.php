<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Illuminate\Contracts\Config\Repository as Config;
use Pushery\SQLens\Audit\ServerLifetime;
use Pushery\SQLens\Capture\Shadow\ProductionConnectionDetector;
use Pushery\SQLens\Capture\Shadow\ShadowTargetIdentity;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;

/**
 * Whether the connection under audit belongs to a production deployment.
 *
 * ## Whose statement `app.env` is
 *
 * `app.env` is what the application running this command says about ITSELF, and so about the
 * database it uses. It says nothing about a server the same command is pointed at from outside: a
 * pipeline with `APP_ENV=testing` or a laptop with `APP_ENV=local` auditing a production connection
 * describes the process, not the server, and read as "not production" it turned a finding about a
 * production server into a pass. So the declaration speaks only for a connection that reaches the
 * application's own server, however many connection names and databases lead there: the server its
 * default connection reaches, and the one `sqlens.security.runtime_connection` names as serving its
 * requests.
 *
 * ## The sources, and the order matters
 *
 * 1. **What the application DECLARES**, for its own server. A declaration beats a guess: a team
 *    that set `APP_ENV=production` has said the thing outright, and a local copy of a production
 *    dump under `APP_ENV=local` is a developer's database whatever it is called.
 * 2. **What the names suggest** — the existing {@see ProductionConnectionDetector}, reused rather
 *    than reimplemented. It reads the connection and database names, and it is a heuristic that
 *    says so: it may say yes and never no.
 * 3. **What the environment declares about the server** — `sqlens.security.server.lifetime`. A
 *    server declared `disposable` is one the pipeline creates and destroys, which is a statement
 *    about the server itself rather than about whoever launched the run.
 *
 * When none of these answers, the verdict is {@see ProductionVerdict::Undetermined} — not "no". A
 * rule that read silence as "not production" would report a pass on a server it never placed.
 *
 * It never connects. The whole question is answered from configuration, which is what makes it
 * usable by a rule that must not open a second session.
 */
final readonly class RunEnvironment
{
    /**
     * Environment names that plainly are not production.
     *
     * A closed list, and deliberately short: every entry is a name Laravel itself or its ecosystem
     * uses. An unknown name falls to `Undetermined` rather than to `NotProduction`, because the
     * whole point of the third value is that guessing "no" is the expensive mistake here.
     *
     * @var list<string>
     */
    public const array NON_PRODUCTION = ['local', 'testing', 'test', 'dev', 'development', 'staging', 'ci', 'sandbox'];

    public function __construct(
        private Config $config,
        private ProductionConnectionDetector $names,
    ) {}

    public function verdict(string $connection): ProductionVerdict
    {
        if ($this->reachesTheApplicationsOwnServer($connection)) {
            $declared = $this->config->get('app.env');
            $declared = is_string($declared) ? strtolower(trim($declared)) : '';

            // `prod` as well as `production`, because both are in the wild and a team that wrote the
            // short one meant the same thing.
            if ($declared === 'production' || $declared === 'prod') {
                return ProductionVerdict::Production;
            }

            if (in_array($declared, self::NON_PRODUCTION, true)) {
                return ProductionVerdict::NotProduction;
            }
        }

        // No declaration that speaks for this server. The names are a heuristic, so they may say
        // "yes" and never "no": an unmarked name is an absence of evidence.
        if ($this->names->isProduction($connection)) {
            return ProductionVerdict::Production;
        }

        return ServerLifetime::declared($this->stringConfig('sqlens.security.server.lifetime'))->isDisposable()
            ? ProductionVerdict::NotProduction
            : ProductionVerdict::Undetermined;
    }

    /**
     * Whether this connection reaches a server the application itself runs on.
     *
     * The SERVER, not the database: what these rules judge are server settings, which every database
     * on one server shares, and a second database on the application's own server is still the
     * application's server. Compared as the framework resolves both, so a `url` counts, and without
     * the credentials: a read-only audit role is the same server. A connection that is not configured
     * reaches nothing, and nothing is nobody's own server.
     */
    private function reachesTheApplicationsOwnServer(string $connection): bool
    {
        return array_any(
            $this->applicationConnections(),
            fn (string $own): bool => $connection === $own || $this->sameServer($connection, $own),
        );
    }

    /**
     * The connections the application declares as its own: the framework's default, and the one it
     * serves requests with where the project named it.
     *
     * @return list<string>
     */
    private function applicationConnections(): array
    {
        return array_values(array_unique(array_filter(
            [$this->stringConfig('database.default'), $this->stringConfig('sqlens.security.runtime_connection')],
            static fn (?string $name): bool => $name !== null,
        )));
    }

    /**
     * Whether two configured connections reach the same server.
     *
     * A host given as a list is a pool the framework picks one member of for each connection, so only
     * the same list is certainly the same server. Reduced to a single name, every list would read as
     * `localhost`, and a remote pool would pass for the application's own database.
     */
    private function sameServer(string $connection, string $other): bool
    {
        $one = EffectiveConnectionConfig::for($this->config->get('database.connections.'.$connection));
        $two = EffectiveConnectionConfig::for($this->config->get('database.connections.'.$other));

        if ($one === [] || $two === []) {
            return false;
        }

        $oneHost = $one['host'] ?? null;
        $twoHost = $two['host'] ?? null;

        if (is_array($oneHost) || is_array($twoHost)) {
            return $oneHost === $twoHost
                && ShadowTargetIdentity::sameInstance([...$one, 'host' => ''], [...$two, 'host' => '']);
        }

        return ShadowTargetIdentity::sameInstance($one, $two);
    }

    private function stringConfig(string $key): ?string
    {
        $value = $this->config->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
