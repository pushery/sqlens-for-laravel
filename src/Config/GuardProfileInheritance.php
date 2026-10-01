<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * A guard profile the package does not ship takes every key it leaves out from the shipped
 * `production` profile.
 *
 * ## Why a profile needs a base at all
 *
 * {@see PublishedConfigMerge} fills a shipped profile that a project published only in part from the
 * shipped profile of the same name. A profile the project ADDED has no such partner, so it reached
 * the guard with exactly the keys somebody wrote, and the guard reads a switch that is not there as
 * off. A `staging` profile naming only `strict.lazy_loading` therefore ran with runtime DDL, unbound
 * raw SQL, slow queries and destructive commands unwatched, although every shipped profile watches
 * them, and the validator called each missing key harmless.
 *
 * ## Why `production`
 *
 * It is written for an environment somebody else runs: it watches and reports and never throws, so
 * it cannot be the reason a page fails, and the guardrails it turns on are ones every shipped
 * profile turns on too. A profile added for staging, a review app or a worker pool starts from
 * those and names only what it wants different, which is what the configuration file has always
 * told a project to do with a profile.
 *
 * It runs where the merge runs, once per boot and before anything reads the guard block. So the
 * guard, `sqlens:doctor` and the configuration validator all read the same complete profile, and a
 * cached configuration carries it.
 */
final readonly class GuardProfileInheritance
{
    /** The shipped profile that a profile the package does not ship inherits from. */
    public const string BASE = 'production';

    /**
     * @param  array<array-key, mixed>  $config  the configuration after the published file was merged in
     * @param  array<array-key, mixed>  $package  the configuration this package ships
     * @return array<array-key, mixed>
     */
    public static function applyTo(array $config, array $package): array
    {
        $shipped = self::profilesOf($package);
        $base = $shipped[self::BASE] ?? null;
        $guard = $config['guard'] ?? null;

        if (! is_array($base) || ! is_array($guard) || ! is_array($guard['profiles'] ?? null)) {
            return $config;
        }

        foreach ($guard['profiles'] as $name => $profile) {
            // A shipped name was already merged over its own shipped profile, and a profile that is
            // not a map is the validator's to refuse rather than this method's to repair.
            if (array_key_exists($name, $shipped) || ! is_array($profile)) {
                continue;
            }

            $guard['profiles'][$name] = PublishedConfigMerge::of($base, $profile);
        }

        $config['guard'] = $guard;

        return $config;
    }

    /**
     * @param  array<array-key, mixed>  $config
     * @return array<array-key, mixed>
     */
    private static function profilesOf(array $config): array
    {
        $guard = $config['guard'] ?? null;
        $profiles = is_array($guard) ? ($guard['profiles'] ?? null) : null;

        return is_array($profiles) ? $profiles : [];
    }
}
