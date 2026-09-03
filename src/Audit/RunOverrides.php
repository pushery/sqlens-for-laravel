<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Reporting\RunContext;

/**
 * The per-run overrides of two configured booleans, carried as one value.
 *
 * `strict_undetermined` and `strict_tools` are both project-level settings that a single run may
 * override from the command line, and both have to reach the {@see RunContext}
 * that every refusal, every early return and every completed reading builds — roughly a dozen places
 * inside the audit, several of which are reached only by a run that never touches a database.
 *
 * ## Why an object rather than a second `?bool` parameter
 *
 * Because of what a MISSED call site would do. Two adjacent nullable booleans threaded by hand
 * through a dozen signatures is a shape where forgetting one at one site compiles, passes every
 * test that does not exercise that particular refusal path, and produces a run that quietly ignores
 * the flag it was given — while its header prints the configured value as though it were in force.
 * That is this package's own silent green, in the code that exists to forbid it.
 *
 * Passed as one value, a missed site is a type error. The compiler enumerates the paths instead of
 * a reader trying to.
 *
 * `null` in either field means "leave the configured value alone", which is not the same as `false`:
 * one declines to decide, the other decides against.
 *
 * There is deliberately no `none()` convenience constructor. It existed for one commit, nothing
 * called it, and a named constructor nobody uses is scaffolding that reads as an API — the two
 * defaulted parameters already say "no overrides" at the one site that needs to.
 */
final readonly class RunOverrides
{
    public function __construct(
        public ?bool $strictUndetermined = null,
        public ?bool $strictTools = null,
    ) {}

    /**
     * This override resolved against the configured value.
     *
     * @param  bool  $configured  what the project configured
     */
    public function strictUndetermined(bool $configured): bool
    {
        return $this->strictUndetermined ?? $configured;
    }

    /**
     * This override resolved against the configured value.
     *
     * @param  bool  $configured  what the project configured
     */
    public function strictTools(bool $configured): bool
    {
        return $this->strictTools ?? $configured;
    }
}
