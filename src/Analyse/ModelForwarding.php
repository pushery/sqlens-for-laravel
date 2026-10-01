<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Eloquent\Model;
use PHPStan\Reflection\ClassReflection;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;

/**
 * Does a call on this model reach the query builder?
 *
 * A model declares neither `whereRaw()` nor `fromQuery()`. It forwards both to a new builder, an
 * instance through `__call` and the class through `__callStatic`, so `Order::whereRaw(…)` is the
 * builder's `whereRaw()` and `$order->fromQuery(…)` the builder's `fromQuery()`.
 *
 * With one exception, and it is a measurement of the model rather than of the name: a model that
 * declares the method itself answers the call with that method, and the forwarding never happens.
 * A named constructor called `fromQuery` is ordinary enough that treating it as raw SQL would
 * report correct code.
 *
 * Shared by every collector that reads a call on a model, statement or fragment, so they cannot
 * come to disagree about which models forward.
 */
final readonly class ModelForwarding
{
    public static function reachesBuilder(Type $model, string $method): bool
    {
        if (! new ObjectType(Model::class)->isSuperTypeOf($model)->yes()) {
            return false;
        }

        return ! array_any(
            $model->getObjectClassReflections(),
            static fn (ClassReflection $class): bool => $class->hasNativeMethod($method),
        );
    }
}
