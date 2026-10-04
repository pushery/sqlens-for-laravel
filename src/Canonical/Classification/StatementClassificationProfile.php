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
     * @param  list<string>  $actionOptions  the keywords that open a table option rather than an
     *                                       action in an `ALTER TABLE` action list, such as MySQL's
     *                                       `ALGORITHM` and `LOCK`: they qualify every action of the
     *                                       statement and do nothing of their own, so they are not
     *                                       classified as one
     * @param  list<string>  $unreservedNames  the keywords, upper case, that the server accepts as an
     *                                         unquoted table, column, index or constraint name, such
     *                                         as PostgreSQL's `type` or MySQL's `date`. A position that
     *                                         takes a name reads one of these as the name it is. Empty
     *                                         keeps every keyword out of a name, so a statement naming
     *                                         an object after one stays undetermined
     */
    public function __construct(
        public array $signatures,
        public array $modifiers,
        public array $leadFallback,
        public array $actionOptions = [],
        public array $unreservedNames = [],
    ) {}
}
