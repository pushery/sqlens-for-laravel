<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

use Pushery\SQLens\Canonical\StatementKind;

/**
 * A driver's complete statement-recognition data, bundled into one artifact so the
 * canonicalization contract grows by a single method. It carries everything the
 * generic classifier needs and nothing engine-specific leaks into the core:
 *
 *  - `signatures` — the ordered shapes, most-specific first;
 *  - `modifiers` — the keywords an OptionalModifiers element may skip (UNIQUE,
 *    CONCURRENTLY, IF, EXISTS, ONLY, …), upper case;
 *  - `leadFallback` — a lead keyword (upper case) → the kind to assign when no
 *    signature matched but the statement is still recognizable (`INSERT` → dml,
 *    `CREATE` → ddl_other, `SET` → unknown). A lead keyword absent here is an
 *    unrecognized form, reported undetermined rather than guessed.
 *
 * An empty `signatures` list is a missing artifact — the classifier reports it as
 * undetermined, never as a silent "everything is unknown".
 */
final readonly class StatementClassificationProfile
{
    /**
     * @param  list<StatementSignature>  $signatures
     * @param  list<string>  $modifiers
     * @param  array<string, StatementKind>  $leadFallback
     */
    public function __construct(
        public array $signatures,
        public array $modifiers,
        public array $leadFallback,
    ) {}
}
