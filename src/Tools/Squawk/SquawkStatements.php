<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Canonical\CanonicalFormVersion;
use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\StatementOrigin;
use Pushery\SQLens\Canonical\TransactionContext;
use Pushery\SQLens\Canonical\TransactionMode;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Capture\CaptureResult;

/**
 * Rebuilds the canonical statements of one captured migration.
 *
 * The pipeline does not keep them. It canonicalizes, stamps the result onto each captured
 * statement as text plus a few resolved facts, and hands the rules subjects — so by the time a
 * tool wants the document, the objects the canonicalization produced are gone and only their
 * output remains.
 *
 * Every field is READ, never re-derived. The transaction mode in particular: the resolver can
 * reach an answer the migrator's own yes/no flag cannot express, and recomputing it from the
 * flag here would quietly overrule the stage whose whole job that was. The flag is used only
 * where the resolver never ran at all, and then it is what the flag says and nothing more.
 */
final readonly class SquawkStatements
{
    /**
     * @return list<CanonicalStatement> in capture order; empty when the migration produced no SQL
     */
    public static function of(CaptureResult $result): array
    {
        $statements = [];

        foreach ($result->statements as $statement) {
            if ($statement->canonicalSql === null) {
                // A statement that never reached canonicalization has no canonical form to send.
                // Skipping it rather than sending the raw text is the grammar-drift guard: raw SQL
                // carries the framework's formatting of the day, so a finding placed on it would
                // move under a Laravel upgrade that changed nothing about the migration.
                continue;
            }

            $statements[] = new CanonicalStatement(
                canonicalSql: $statement->canonicalSql,
                origin: new StatementOrigin(
                    $result->file,
                    $result->migrationClass,
                    $statement->sequence,
                    $statement->direction,
                ),
                transaction: self::transaction($statement),
                formVersion: CanonicalFormVersion::current(),
                statementKind: $statement->statementKind,
                targets: $statement->targets,
                keyColumns: $statement->keyColumns,
            );
        }

        return $statements;
    }

    /**
     * The resolved transaction context when the resolver produced one, the migrator's flag when
     * it did not.
     *
     * Never the other way round. The resolver knows about explicit markers and driver
     * capabilities and can answer "undetermined"; the flag is yes-or-no and cannot. Preferring
     * the flag would flatten a third answer into a second one, which is exactly how a
     * lock-hygiene rule goes silent on the statement it could not reason about.
     */
    private static function transaction(CapturedStatement $statement): TransactionContext
    {
        return $statement->transactionMode instanceof TransactionMode
            ? new TransactionContext($statement->transactionMode)
            : TransactionContext::fromMigratorFlag($statement->withinTransaction);
    }
}
