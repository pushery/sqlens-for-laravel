<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * One action of an `ALTER TABLE` action list, classified on its own.
 *
 * `ALTER TABLE users ADD COLUMN nickname text, DROP COLUMN legacy` is one statement: one lock, one
 * rewrite, one entry in the migration. Its kind comes from its first action, because that is where
 * the signatures match, and read that way the `DROP COLUMN` reached no rule. So each later action
 * that does something else, or the same to another object, is classified by itself, against the
 * same signatures, and carried here: what it does, and what it acts on. `drop a, drop b` is how
 * Laravel drops two columns, and the second is an action of its own.
 *
 * It stays part of the statement it came from. The canonical text, the position and the transaction
 * are the statement's, so a rule judging an action reads the same statement and sees a different
 * part of it.
 */
final readonly class StatementAction
{
    /**
     * @param  list<StatementTarget>  $targets
     * @param  list<string>  $keyColumns
     * @param  list<ColumnDefinition>|null  $columnDefinitions
     */
    public function __construct(
        public StatementKind $kind,
        public array $targets,
        public array $keyColumns = [],
        public ?array $columnDefinitions = null,
    ) {}
}
