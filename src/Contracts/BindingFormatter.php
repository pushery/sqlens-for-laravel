<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * The few pieces of binding rendering that genuinely differ per engine.
 *
 * Everything else about substitution — placeholder scanning, the type matrix,
 * the count check — is identical everywhere and lives in the driver-neutral
 * core. Only what the engines actually disagree about is behind this seam, so
 * the core carries no DB specifics and a third driver implements a handful of
 * methods rather than a second substitutor.
 */
interface BindingFormatter
{
    /**
     * How this engine writes a boolean literal. PostgreSQL takes `true`/`false`;
     * MySQL takes `1`/`0`. Rendering the wrong one is not a syntax error there —
     * it silently becomes a different value, which is exactly the kind of quiet
     * mistranslation a rule would then read as fact.
     */
    public function booleanLiteral(bool $value): string;

    /** The date format this engine's grammar uses for a timestamp literal. */
    public function dateFormat(): string;
}
