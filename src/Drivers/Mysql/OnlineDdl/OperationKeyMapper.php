<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The bridge from a canonical statement to the key the online-DDL matrix is keyed on.
 *
 * The matrix answers questions about an OPERATION ("add_column", "drop_index"); the
 * canonicalization produces a STATEMENT with a kind and its targets. Nobody translated between
 * the two, so a rule had nothing to look a downtime class up with — and the obvious workaround,
 * matching the SQL text, is the grammar-drift trap the canonicalization layer exists to prevent.
 *
 * It reads the classified kind and nothing else. No SQL text, no grammar shapes: those belong to
 * the classifier, which already turned them into a kind through its signature machinery. A second matcher
 * here would duplicate work the classifier already does.
 *
 * WHAT IT DELIBERATELY DOES NOT DO YET, so the limit is visible rather than assumed. Three kinds
 * map one-to-one onto a matrix operation. The others are RECOGNIZED but too coarse to key on:
 * {@see StatementKind::AlterColumn} covers a type change, a VARCHAR resize in either direction and
 * a nullability flip — six matrix operations whose difference lives in the type expression, which
 * the kind does not carry. The index builds are now separated too, so only
 * one coarse case is left.
 * {@see StatementKind::AddConstraint} stays the GENERIC named constraint (a CHECK, a
 * UNIQUE) that the matrix does not classify as one operation.
 *
 * Those return a NAMED undetermined rather than a guess. Picking the most likely operation would
 * be the silent-green this package exists to refuse — and picking the most expensive one would
 * cry wolf on every ordinary migration. Narrowing them needs a finer signal than the kind, which
 * is a design decision on the classification layer rather than something to improvise here.
 */
final readonly class OperationKeyMapper
{
    /**
     * The kinds that name exactly one matrix operation. Kept as data rather than a match, so the
     * set that is decidable today is readable at a glance next to the set that is not.
     *
     * @var array<string, string>
     */
    private const array DIRECT = [
        StatementKind::AddColumn->value => 'add_column',
        StatementKind::DropColumn->value => 'drop_column',
        StatementKind::DropIndex->value => 'drop_index',
        StatementKind::AddPrimaryKey->value => 'add_primary_key',
        StatementKind::AddForeignKey->value => 'add_foreign_key',
        StatementKind::CreateIndex->value => 'add_secondary_index',
        StatementKind::CreateFulltextIndex->value => 'add_fulltext_index',
        StatementKind::CreateSpatialIndex->value => 'add_spatial_index',
    ];

    /**
     * The operation key for a statement, or a named reason why none could be derived.
     */
    public function map(CanonicalStatement $statement): OperationKeyResolution
    {
        return $this->forKind($statement->statementKind);
    }

    /**
     * The same mapping from the KIND alone — the form a rule uses.
     *
     * A rule never sees a {@see CanonicalStatement}; it sees the canonical view, which carries the
     * kind and nothing that would let it rebuild one. This is the primitive both entry points share,
     * so a rule and the runner can never map the same kind two different ways — and it is not a
     * second reading, because {@see map()} never read anything else in the first place.
     */
    public function forKind(?StatementKind $kind): OperationKeyResolution
    {
        if (! $kind instanceof StatementKind) {
            return OperationKeyResolution::undetermined(
                UndeterminedReason::OperationKeyUnmapped,
                'the statement was never classified, so it carries no kind to derive an operation from',
            );
        }

        $key = self::DIRECT[$kind->value] ?? null;

        if ($key === null) {
            return OperationKeyResolution::undetermined(
                UndeterminedReason::OperationKeyUnmapped,
                "statement kind '{$kind->value}' does not name a single online-DDL operation",
            );
        }

        return OperationKeyResolution::resolved($key);
    }
}
