<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * PostgreSQL's `money` type — the one that looks like the right answer.
 *
 * ## Three problems, and the first one is silent
 *
 * **Its input and output depend on a server setting.** `money` is parsed and rendered through
 * `lc_monetary`. A dump taken on a server whose locale writes `1.234,56` and restored onto one that
 * writes `1,234.56` does not fail — it reads the same characters as a different number. That is a
 * data corruption whose only evidence is the amount itself.
 *
 * **It carries no currency.** The name promises otherwise, and a column called `price` of type
 * `money` reads like it knows what currency it is in. It does not; the currency lives in a locale
 * setting that is a property of the SERVER, not of the row.
 *
 * **Its scale is fixed by that same setting.** How many fractional digits are kept is not a
 * property of the column, so two servers can disagree about how much of an amount to keep.
 *
 * ## Why this is not folded into the float rule
 *
 * {@see FloatForMoneyRule} answers a different question. It needs a name heuristic, because nothing
 * in a catalog says a column holds money — here the TYPE is the whole finding, with no guessing at
 * all. The two also fail differently: a float loses cents to arithmetic, `money` changes meaning
 * when the server does. A project may reasonably accept one and not the other, and separate ids are
 * what makes that possible.
 *
 * The recommendation is nonetheless the same, and the docs say so plainly rather than pretending
 * two roads lead to two places: `numeric(19, 4)`, with the currency in a column of its own.
 *
 * ## An ARRAY is covered; a DOMAIN is not, and both facts were measured
 *
 * `money[]` is reported. The catalog spells it `money[]`, and the canonicalizer strips the array
 * marker from the NAME while the raw spelling keeps it — so the column arrives here as `money`. An
 * array of amounts carries exactly the same locale problem, and a silent miss would have looked
 * like a clean table.
 *
 * A DOMAIN over `money` is NOT reported, and cannot be. The catalog reports the domain's own name
 * (`CREATE DOMAIN eur AS money` yields a column of type `eur`), so nothing here can see the money
 * underneath — and there is no undetermined to emit either, because the rule has no way to know the
 * type is a domain at all rather than an ordinary user type it correctly has nothing to say about.
 * Naming the limit is the honest form; a live test asserts it so it stays a documented boundary
 * rather than a surprise.
 */
final class MoneyTypeRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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

    public function id(): string
    {
        return 'PG.L5.MONEY_TYPE';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

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

        $columns = [];

        foreach (ForeignKeyIndexCoverage::parse($object->getString('column_types') ?? '') as $column => $types) {
            if (mb_strtolower($types[0] ?? '') === 'money') {
                $columns[] = (string) $column;
            }
        }

        sort($columns);

        if ($columns === []) {
            return [];
        }

        // ONE verdict for the table. A catalog finding is located at the object and results are
        // deduplicated by rule id and location, so a verdict per column would arrive as one with
        // the rest dropped without a word.
        return [RuleVerdict::flag(sprintf(
            'On %s, %s of type money: %s. The type looks like the right answer and is not: it is parsed and '
            .'rendered through lc_monetary, so a dump restored onto a server with another locale reads the same '
            .'characters as a different number — no error, no warning, just a different amount. It also carries '
            .'no currency of its own, though the name suggests it does, and its scale is fixed by that same '
            .'server setting rather than by the column. Use numeric(19, 4) and keep the currency in a column '
            .'beside it. Changing the type rewrites the table; the lint suite classifies that operation and '
            .'carries its downtime class.',
            $object->qualifiedName,
            count($columns) === 1 ? 'a column is' : count($columns).' columns are',
            implode(', ', $columns),
        ))];
    }
}
