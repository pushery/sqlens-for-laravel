<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Illuminate\Support\ServiceProvider;
use Pushery\SQLens\Console\ApiSnapshotCommand;
use Pushery\SQLens\Console\CorpusMeasureCommand;

/**
 * The commands that exist for developing SQLens itself, and are NOT part of its public surface.
 *
 * ## Why a second provider rather than a flag
 *
 * From 1.0 the `sqlens:*` commands are promised API. What makes a command part of that promise is
 * not intent but REGISTRATION: a command in the regular provider appears in every consuming
 * application's `artisan list`, and once it is there, removing it is a breaking change.
 *
 * A conditional inside the regular provider — `if ($this->app->environment('local'))` — would fail
 * that test in the worst way, because a consumer developing locally would see it and could
 * reasonably build on it. The boundary has to be one a consumer cannot cross by accident.
 *
 * So this provider exists and **nothing auto-discovers it**: `composer.json` declares exactly one
 * provider under `extra.laravel.providers`, and it is not this one. A repository that wants these
 * commands registers it by hand, which this package's own test bootstrap does.
 *
 * The rule is held by a test rather than by this docblock: an ordinary application is booted and
 * asserted not to know `sqlens:corpus-measure`. A sentence would not survive somebody moving a line
 * into the wrong provider.
 */
final class SQLensDevelopmentServiceProvider extends ServiceProvider
{
    /**
     * Every command that is deliberately outside the promised surface.
     *
     * A list rather than one entry, because the second one is where the reasoning gets forgotten —
     * whoever adds it should find the boundary already stated here rather than have to reconstruct
     * it.
     *
     * @var list<class-string>
     */
    public const array COMMANDS = [
        ApiSnapshotCommand::class,
        CorpusMeasureCommand::class,
    ];

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands(self::COMMANDS);
        }
    }
}
