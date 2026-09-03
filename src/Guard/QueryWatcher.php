<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Guard\Contracts\AccumulatesPerWindow;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\Contracts\RuntimeGuard;

/**
 * The ONE query listener the guard suite registers, however many query-based guardrails are on.
 *
 * ## Why one and not N
 *
 * Every listener on `QueryExecuted` runs for every query an application executes. Three guardrails
 * with a listener each is three closures on the hot path of a request that might run four hundred
 * queries — a cost that grows with the feature list, in a package whose whole promise is that it
 * only reads. One listener that fans out costs one closure, whatever gets added later.
 *
 * ## It applies to nothing when nothing asks for it
 *
 * `appliesTo()` answers false when no inspector wants this profile, so a profile that only sets
 * Eloquent strictness registers no query listener at all. "Off" has to mean absent rather than
 * cheap, and this is where that promise is actually kept for the expensive half of the suite.
 *
 * ## The connection filter lives here
 *
 * A profile may name the connections it watches. Applying that once, before the fan-out, is what
 * keeps every inspector free of the question — and what makes "this guardrail is off for that
 * connection" one line rather than a rule each inspector has to remember.
 */
final readonly class QueryWatcher implements RuntimeGuard
{
    /** @param list<QueryInspector> $inspectors in the order they will judge a query */
    public function __construct(private Dispatcher $events, private array $inspectors = []) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return array_any($this->inspectors, fn (QueryInspector $inspector): bool => $inspector->appliesTo($profile));
    }

    /**
     * The lifecycle events that end one accounting window, listened for BY NAME.
     *
     * String class-names rather than imports, and that is a dependency decision rather than a style
     * one: `RequestHandled` lives in `illuminate/foundation` and the job events in
     * `illuminate/queue`, neither of which this package requires. Listening by name costs nothing
     * when the event never fires, and works exactly as well when it does.
     *
     * ⚠️ Without these the cumulative budget is dead from the second job onward in any long-lived
     * process — and dead in the way that looks healthiest: the log reports once and then goes quiet
     * forever, which reads like an application that got faster.
     *
     * @var list<string>
     */
    private const array WINDOW_ENDS = [
        'Illuminate\Foundation\Http\Events\RequestHandled',
        'Illuminate\Queue\Events\JobProcessing',
        'Illuminate\Console\Events\CommandStarting',
    ];

    public function activate(GuardProfile $profile): void
    {
        // Resolved ONCE, at activation, rather than per query. Which inspectors a profile wants
        // cannot change during a request — the profile is immutable — so asking every query would
        // be the same answer computed four hundred times.
        $active = array_values(array_filter(
            $this->inspectors,
            static fn (QueryInspector $inspector): bool => $inspector->appliesTo($profile),
        ));

        $this->events->listen(QueryExecuted::class, static function (QueryExecuted $query) use ($active, $profile): void {
            if (! $profile->watches($query->connectionName)) {
                return;
            }

            foreach ($active as $inspector) {
                $inspector->inspect($query, $profile);
            }
        });

        $windowed = array_values(array_filter(
            $active,
            static fn (QueryInspector $inspector): bool => $inspector instanceof AccumulatesPerWindow,
        ));

        if ($windowed === []) {
            return;
        }

        foreach (self::WINDOW_ENDS as $event) {
            $this->events->listen($event, static function () use ($windowed): void {
                foreach ($windowed as $inspector) {
                    $inspector->startWindow();
                }
            });
        }
    }
}
