<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Money\FloatingMoneyColumns;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A money column kept in a floating-point type.
 *
 * The judgment — which types cannot hold money, and when a column's NAME is evidence enough — is
 * shared with the MySQL sister through {@see FloatingMoneyColumns}. What is PostgreSQL's own is the
 * remedy: `numeric`, which this engine spells that way and stores as digits.
 *
 * ## Why `money` is somebody else's finding
 *
 * PostgreSQL has a type literally called `money`, and it is not the answer — but it is also not
 * this rule's business. It needs no name heuristic at all (the type IS the finding), it fails for a
 * different reason (its input and output hang on `lc_monetary`, and it carries no currency), and it
 * has a different remediation story. It lives in {@see MoneyTypeRule} under its own id, so a
 * project can accept one and not the other.
 */
final class FloatForMoneyRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    private readonly MoneyColumnDictionary $dictionary;

    public function __construct(string $projectRoot, ?MoneyColumnDictionary $dictionary = null)
    {
        parent::__construct($projectRoot);

        $this->dictionary = $dictionary ?? MoneyColumnDictionary::bundled();
    }

    public function id(): string
    {
        return 'PG.L5.FLOAT_MONEY';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    /**
     * Safety, not idiom, and the line is worth stating: what this reports is arithmetic that comes
     * out wrong. The name heuristic is a guess about INTENT, but once the intent is money the
     * consequence is not a matter of taste.
     */
    public function category(): Category
    {
        return Category::Safety;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $columns = FloatingMoneyColumns::on($object, $this->dictionary);

        if ($columns === []) {
            return [];
        }

        $named = [];

        foreach ($columns as $column => $type) {
            $named[] = $column.' ('.$type.')';
        }

        return [RuleVerdict::flag(sprintf(
            'On %s, %s named like money but held as a binary float: %s. A float cannot represent 0.10 exactly, '
            .'so ten of them do not add up to 1.00 — near enough that every screen shows 1.00 and every '
            .'comparison against it fails. The error surfaces as one cent on a statement months later, with no '
            .'way back to the column. Use numeric(19, 4): it stores the digits, so the arithmetic is the '
            .'arithmetic of the invoice. Note that this is a HEURISTIC on the column NAME — nothing in a '
            .'catalog says a column holds money — so a %s that is not monetary belongs on the ignore list or '
            .'in sqlens.audit.money_columns.ignore. Changing the type rewrites the table; the lint suite '
            .'classifies that operation and carries its downtime class.',
            $object->qualifiedName,
            count($columns) === 1 ? 'a column is' : count($columns).' columns are',
            implode(', ', $named),
            count($columns) === 1 ? 'name' : 'name among them',
        ))];
    }
}
