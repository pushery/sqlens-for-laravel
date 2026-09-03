<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Illuminate\Contracts\Config\Repository as Config;
use Pushery\SQLens\Capture\Shadow\ProductionConnectionDetector;

/**
 * Whether the connection under audit belongs to a production deployment.
 *
 * ## Two sources, and the order matters
 *
 * 1. **What the application DECLARES** — `app.env`. A declaration beats a guess: a team that set
 *    `APP_ENV=production` has said the thing outright, and reading a name instead would let a
 *    database called `shop` overrule it.
 * 2. **What the names suggest** — the existing {@see ProductionConnectionDetector}, reused rather
 *    than reimplemented. It reads the connection and database names, and it is a heuristic that
 *    says so.
 *
 * When the declaration is a value nobody here recognizes and the names say nothing either, the
 * answer is {@see ProductionVerdict::Undetermined} — not "no". A rule that read silence as "not
 * production" would report a pass on a server it never placed.
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
        $declared = $this->config->get('app.env');
        $declared = is_string($declared) ? strtolower(trim($declared)) : '';

        // The declaration first. `prod` as well as `production`, because both are in the wild and a
        // team that wrote the short one meant the same thing.
        if ($declared === 'production' || $declared === 'prod') {
            return ProductionVerdict::Production;
        }

        if (in_array($declared, self::NON_PRODUCTION, true)) {
            return ProductionVerdict::NotProduction;
        }

        // No usable declaration. The names are a heuristic, so they may say "yes" — they may never
        // say "no": an unmarked name is an absence of evidence, and reading it as evidence of
        // absence is exactly the mistake the third value exists for.
        return $this->names->isProduction($connection)
            ? ProductionVerdict::Production
            : ProductionVerdict::Undetermined;
    }
}
