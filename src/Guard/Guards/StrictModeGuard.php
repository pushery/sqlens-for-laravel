<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Guard\Contracts\RuntimeGuard;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Guard\Violations\Violation;

/**
 * Eloquent's own strictness switches, set from configuration instead of from `AppServiceProvider`.
 *
 * ## Why a package sets switches an application could set itself
 *
 * It could, and most do not — because the four calls live in `boot()`, they are easy to write
 * differently per environment by accident, and the one that matters most in production
 * (`preventLazyLoading`) is the one people are most afraid to turn on. Moving them into a named
 * profile makes the environment difference a line of configuration that is reviewed rather than a
 * conditional in application code that is not.
 *
 * ## `throw` is the whole design, and it defaults to false
 *
 * `preventLazyLoading(true)` THROWS. On a developer's machine that is the fastest feedback there is;
 * in production it turns a slow page into a broken one, over a relationship that would have loaded.
 * So the shipped behavior is to report through {@see ViolationLogger} and let the request finish,
 * and `strict.throw` is the deliberate opt-in for the environments where stopping is better.
 *
 * Laravel supports exactly this with `handleLazyLoadingViolationUsing()` and friends: the switch
 * stays on, and the HANDLER decides what happens. Turning the switch off instead would mean nothing
 * is detected at all.
 */
final readonly class StrictModeGuard implements RuntimeGuard
{
    public function __construct(private ViolationLogger $logger) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->lazyLoading
            || $profile->discardingAttributes
            || $profile->missingAttributes
            || $profile->destructiveCommands;
    }

    public function activate(GuardProfile $profile): void
    {
        // ⚠️ THE MASKING CASE, and it is reported BEFORE anything is armed.
        //
        // Laravel's automatic eager loading resolves a relation before `preventLazyLoading` can
        // object, so with both on, the guardrail never fires — and never fires is exactly what a
        // working guardrail on a clean application looks like. A project would read a silent log as
        // proof there are no lazy loads, when the truth is that nothing could have detected one.
        //
        // Undetermined rather than a refusal: the combination is legitimate, and auto eager loading
        // is arguably the better answer to the same problem. What is not legitimate is believing
        // both are working.
        if ($profile->lazyLoading && Model::isAutomaticallyEagerLoadingRelationships()) {
            $this->logger->record($profile, Violation::undetermined(
                type: 'guardrail_masked',
                category: Category::Safety,
                message: 'the lazy-loading guardrail cannot prove it checks anything while automatic '
                    .'eager loading is on. Laravel resolves the relation first, so a violation never '
                    .'reaches this guardrail and a silent log is not evidence that there are none. '
                    .'Turn one of the two off.',
                reason: 'automatic_eager_loading',
                sql: 'Model::automaticallyEagerLoadRelationships()',
            ));
        }

        Model::preventLazyLoading($profile->lazyLoading);
        Model::preventSilentlyDiscardingAttributes($profile->discardingAttributes);
        Model::preventAccessingMissingAttributes($profile->missingAttributes);

        if ($profile->destructiveCommands) {
            // Laravel's own prohibition on `migrate:fresh`, `db:wipe` and friends. Unlike the three
            // above it has no reporting variant and needs none: there is no version of running one
            // of those against production that anybody wanted.
            DB::prohibitDestructiveCommands(true);
        }

        if ($profile->throw) {
            // The switches throw by themselves. Registering handlers here would REPLACE that, so a
            // profile asking to be stopped would instead be logged — the opposite of what it asked
            // for.
            return;
        }

        $logger = $this->logger;

        Model::handleLazyLoadingViolationUsing(static function (Model $model, string $relation) use ($logger, $profile): void {
            $logger->record($profile, Violation::found(
                type: 'lazy_loading',
                category: Category::Performance,
                message: 'a lazy load happened where the profile forbids one',
                sql: sprintf('%s::$%s', $model::class, $relation),
                context: ['model' => $model::class, 'relation' => $relation],
            ));
        });

        Model::handleDiscardedAttributeViolationUsing(static function (Model $model, array $keys) use ($logger, $profile): void {
            // The attribute NAMES and never their values. A discarded attribute is by definition
            // something somebody tried to write, so its value is user input — and a log is not where
            // that belongs.
            $logger->record($profile, Violation::found(
                type: 'discarding_attributes',
                category: Category::Safety,
                message: 'attributes were silently discarded',
                sql: $model::class,
                context: ['model' => $model::class, 'attributes' => array_values($keys)],
            ));
        });

        Model::handleMissingAttributeViolationUsing(static function (Model $model, string $key) use ($logger, $profile): void {
            $logger->record($profile, Violation::found(
                type: 'missing_attributes',
                category: Category::Safety,
                message: 'an attribute that was never retrieved was read',
                sql: sprintf('%s::$%s', $model::class, $key),
                context: ['model' => $model::class, 'attribute' => $key],
            ));
        });
    }
}
