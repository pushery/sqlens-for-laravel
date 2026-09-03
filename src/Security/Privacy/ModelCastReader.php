<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Illuminate\Database\Eloquent\Model;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * What an application's Eloquent models say about the columns of a table.
 *
 * Whether a column is encrypted is a fact about the MODEL, not about the catalog — the database
 * shows a `text` either way. This class is the bridge, and it is built to be wrong in one direction
 * only: when it cannot answer, it says so rather than guessing the comfortable answer.
 *
 * ## `getCasts()` on a constructed model, and no cheaper way is also correct
 *
 * Measured in the spike behind this class: a model's `casts()` METHOD is merged into the cast list
 * at construction, so static reflection over the `$casts` property misses every model written the
 * modern way. Constructing is therefore not laziness, it is the only reading that sees what Laravel
 * sees.
 *
 * It opens no connection. `getCasts()` was measured against a model whose connection no config
 * defines, and answered; a second arm proved that connection really was unusable, so the silence is
 * a result rather than a coincidence.
 *
 * ## `ModelInspector` is NOT the way, although it looks purpose-built
 *
 * `php artisan model:show` reports casts, so the first instinct of a later reader is
 * `Illuminate\Database\Eloquent\ModelInspector`. It is disqualified twice, both measured: it
 * CONNECTS — it dies reaching for the connection name before anything asks it about a cast — and
 * its relation pass invokes every relation method by reflection, which is a host application's own
 * code running because a linter looked at it. Both are straight against primum non nocere.
 *
 * ## The cost, and why it is acceptable
 *
 * Constructing a model runs `bootIfNotBooted()`: `boot()`, every trait's boot method, and the
 * booting/booted events — a host application may put anything in there. Measured: that happens once
 * per CLASS per process, not once per instance. A run that walks many models pays it once each.
 */
final class ModelCastReader
{
    /** @var array<string, array<string, array<string, string>>>|null table => class => casts */
    private ?array $index = null;

    /** @var array<string, string> class => the reason its casts are unreadable */
    private array $unreadable = [];

    /** @var array<string, UndeterminedReason> class => which kind of unreadable */
    private array $unreadableKind = [];

    /**
     * @param  list<class-string<Model>>  $models  the model classes to ask, already resolved
     */
    public function __construct(private readonly array $models) {}

    /**
     * What the application's models say about one column.
     *
     * The order of the checks is the order of the answers a reader can act on: no model at all is a
     * different errand from a broken model, and both are different from a cast nobody may execute.
     */
    public function protectionFor(string $table, string $column): ColumnProtection
    {
        $byClass = $this->index()[$table] ?? [];

        if ($byClass === []) {
            // A model that would not construct never reported a table, so "no model maps to this
            // one" cannot be said while any model is unreadable — the missing one may be exactly
            // that model. The weaker, true answer is given instead of the tidy, unfounded one.
            $broken = $this->unreadableModels();

            if ($broken !== []) {
                return ColumnProtection::undetermined(
                    $this->firstUnreadableKind(),
                    $table.' — unreadable models: '.implode(', ', array_keys($broken)),
                );
            }

            return ColumnProtection::undetermined(UndeterminedReason::ModelNotFound, $table);
        }

        $verdicts = [];

        foreach ($byClass as $casts) {
            $cast = $casts[$column] ?? null;

            if ($cast === null) {
                $verdicts['unprotected'] = ColumnProtection::unprotected();

                continue;
            }

            // Checked BEFORE the family, because a custom castable is the one answer no amount of
            // agreement between models could make safe.
            if (EncryptedCasts::isCustomCastable($cast)) {
                return ColumnProtection::undetermined(UndeterminedReason::CustomCastOpaque, $cast);
            }

            if (EncryptedCasts::protects($cast)) {
                $verdicts['protected:'.$cast] = ColumnProtection::protected($cast);

                continue;
            }

            $verdicts['unprotected'] = ColumnProtection::unprotected();
        }

        // Two models, two answers. Neither is preferred — see ConflictingModelCasts.
        if (count($verdicts) > 1) {
            return ColumnProtection::undetermined(
                UndeterminedReason::ConflictingModelCasts,
                $table.'.'.$column,
            );
        }

        return array_values($verdicts)[0];
    }

    /**
     * Whether every model this reader was given failed to answer.
     *
     * The summary line the guardrail asks for: a run in which nothing could be determined must say
     * so, because a privacy pack that quietly determines nothing is the worst version of itself.
     */
    public function readNothing(): bool
    {
        $this->index();

        return $this->models !== [] && $this->index === [];
    }

    /** @return array<string, string> class => reason, for a report that wants to name them */
    public function unreadableModels(): array
    {
        $this->index();

        return $this->unreadable;
    }

    /** The kind of the first unreadable model, in the order they were given. */
    private function firstUnreadableKind(): UndeterminedReason
    {
        return array_values($this->unreadableKind)[0] ?? UndeterminedReason::ModelNotConstructible;
    }

    /**
     * @return array<string, array<string, array<string, string>>>
     */
    private function index(): array
    {
        if ($this->index !== null) {
            return $this->index;
        }

        $index = [];

        foreach ($this->models as $class) {
            try {
                $first = new $class;
                $casts = $first->getCasts();

                // Constructed a SECOND time on purpose: `casts()` is a method and may read request
                // state, and a list that differs between two fresh instances describes no schema
                // fact. Freezing whichever came first would make the finding depend on walk order.
                if ((new $class)->getCasts() !== $casts) {
                    $this->markUnreadable($class, UndeterminedReason::ModelCastsNotStatic, $class);

                    continue;
                }

                $table = $first->getTable();
            } catch (Throwable $e) {
                $this->markUnreadable($class, UndeterminedReason::ModelNotConstructible, $class.': '.$e->getMessage());

                continue;
            }

            $narrowed = [];

            foreach ($casts as $attribute => $cast) {
                // Narrowed explicitly rather than cast wholesale: a cast declaration that is not a
                // string is not one this class can reason about, and turning it into one with
                // strval() would invent a name to compare against the family.
                if (is_string($attribute) && is_string($cast)) {
                    $narrowed[$attribute] = $cast;
                }
            }

            $index[$table][$class] = $narrowed;
        }

        return $this->index = $index;
    }

    private function markUnreadable(string $class, UndeterminedReason $kind, string $detail): void
    {
        $this->unreadable[$class] = $detail;
        $this->unreadableKind[$class] = $kind;
    }
}
