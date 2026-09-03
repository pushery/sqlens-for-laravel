<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TransactionMode;

/**
 * One entry in a migration's ordered statement stream — the canonical facts a rule
 * needs to reason about a statement OTHER than the one it is judging.
 *
 * Most rules judge a statement in isolation, or against migration-wide facts already
 * distilled onto {@see MigrationContext} (was this table created here? does this
 * migration drop a constraint?). A few cannot: "does the stream set a lock timeout
 * BEFORE the first lock-taking statement?" is a question about ORDER, and order is
 * lost the moment the migration is reduced to a set of booleans. So the context also
 * carries the statements themselves, in capture order, as these digests.
 *
 * It is deliberately the same class of canonical fact the {@see MigrationStatementView}
 * exposes for the judged statement — the normalized string, what it does, whether it
 * runs in a transaction — and nothing more: no raw grammar, no provenance, no source
 * file. A rule walking the stream sees exactly what it sees for the one statement it
 * judges, just for the neighbors too. The classification is driver-NEUTRAL
 * ({@see StatementKind} names what a statement does, not how any one engine locks for
 * it); a driver rule applies its own engine reading on top (which of these kinds takes
 * a strong lock is a PostgreSQL question, answered under Drivers\Pgsql).
 */
final readonly class MigrationStatementDigest
{
    use SelectsStatementTargets;

    /** @param  list<StatementTarget>  $targets  the classified targets, empty when unclassified */
    public function __construct(
        /** The statement's position in the migration, its capture sequence — the stream is ordered by this. */
        public int $index,
        /** What the statement does, or null when the driver could not classify it. */
        public ?StatementKind $kind,
        /** The normalized statement string — never the raw grammar output. */
        public string $canonical,
        /** Whether this statement runs inside a transaction (the migration's own `$withinTransaction`). */
        public bool $withinTransaction,
        public array $targets = [],
        /** The resolved transaction mode, or null when the statement never reached canonicalization. */
        public ?TransactionMode $transactionMode = null,
        /**
         * The ordered column list this statement names — an index's key columns, a foreign key's
         * referencing columns — or an empty list when it names none.
         *
         * ORDER is load-bearing and is why this is a list rather than a set. Index coverage is a
         * LEFT PREFIX: an index on `(a, b)` answers a lookup on `(a)` and on `(a, b)`, and answers
         * nothing for `(b)`. A set would make the one question this field exists for unanswerable,
         * while looking like it had been answered.
         *
         * Produced by the CLASSIFIER, from the statement signature — never by a rule re-reading the
         * canonical string. Reading grammar in a rule is what this layer exists to prevent, and the
         * docblock above says so about every other field here.
         *
         * @var list<string>
         */
        public array $keyColumns = [],
    ) {}

    /** Whether this statement's transaction context could not be resolved. */
    public function transactionContextUnknown(): bool
    {
        return $this->transactionMode === TransactionMode::Undetermined;
    }
}
