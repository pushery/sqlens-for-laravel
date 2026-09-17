<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L8;

use Pushery\SQLens\Catalog\Understanding\CaseFoldedKey;
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
 * A unique index over a case-folded column is a guarantee the application has to know about.
 *
 * `CREATE UNIQUE INDEX … ON users ((lower(email)))` says two rows may not share an address once case
 * is folded away. Nothing about that is wrong, and this rule reports no defect in the schema — the
 * index is doing exactly what whoever wrote it meant. What it reports is that the guarantee EXISTS,
 * because it is invisible from the application side: the column still reads `email`, a model still
 * says `unique:users,email`, and every ordinary lookup compares the column rather than its folded
 * form.
 *
 * ## Why that is worth a line of report
 *
 * The two halves have to agree or the database answers a question the code did not ask. A check
 * written `where('email', $input)` finds nothing for an address already taken under a different
 * case, so the code concludes the address is free — and the insert behind it is then refused by the
 * index. The failure lands at the write, in a place that looks like a database fault rather than a
 * mismatched comparison, and the difference between "not found" and "refused" is observable from
 * outside. On an endpoint built not to disclose whether an account exists, that difference is the
 * disclosure.
 *
 * So the remedy is never to drop the index. It is to compare the way the index does, or to fold on
 * the way in so that both sides hold the same value.
 *
 * ## Why convention, and not security
 *
 * The finding names a correct schema. `Category::Security` and `Category::Privacy` are the two that
 * bypass the level gate and answer to severity instead (see `Category::usesSeverityGate()`), so a
 * rule filed there reaches every consumer at every strictness — and a security finding that points
 * at something intact is how a security finding stops meaning "this is broken". The vulnerability in
 * the case this was built for lived in the application's comparison, which no reader of a database
 * can see.
 *
 * ## Why level 8, where the other convention rules are
 *
 * Levels are cumulative, so a lower level reaches MORE consumers, not fewer. Level 6 is the type
 * idiom band — `timestamptz`, `jsonb`, identity columns — and a statement about an index belongs to
 * none of that. Level 8 is "naming schemes and structural house style", which is what a deliberate
 * functional unique index is, and it is the band a consumer turns on when they want to be told about
 * considered structural decisions rather than about defects.
 *
 * ## What it cannot see
 *
 * - **The application.** This rule reads a database. Whether the code compares the same way is the
 *   half that actually decides the outcome, and no catalog says.
 * - **The same guarantee reached another way.** A `citext` column, or a column under a
 *   case-insensitive collation, carries an ordinary unique index and promises the same thing with no
 *   expression to recognize. Those are silent here, and a reader should not take this rule's silence
 *   for "nothing in this schema folds case".
 * - **A fold wrapped in anything else.** `lower(btrim(email))` is unique over a value that is folded
 *   AND trimmed, so the sentence this rule would print about it would be false; {@see CaseFoldedKey}
 *   refuses it rather than approximate it.
 * - **MySQL**, which has no sister rule by absence rather than by oversight: its default collations
 *   are already case-insensitive, so the guarantee is usually the column's own and a functional
 *   unique index over `lower()` is rare there.
 */
final class UniqueCaseFoldedIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — the guarantee belongs to a table, and every index of it arrives as one of its
     * members. A run that read no table produced no subject, and the report has to be able to say
     * that rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L8.UNIQUE_CASE_FOLDED';
    }

    public function level(): Level
    {
        return Level::Conventions;
    }

    public function category(): Category
    {
        return Category::Convention;
    }

    /**
     * Audit only, and deliberately NOT `Suite::Security`.
     *
     * The suite axis is independent of the category one, so a security suite membership would be
     * legal here — and it would put a finding about an intact schema in front of the reader who asked
     * what is broken. The reasoning is the same one the class docblock gives for the category, and
     * the two are kept in step on purpose.
     *
     * @return list<Suite>
     */
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

        $folded = [];

        // `unique_indexes` carries every unique index that is not the primary key, and it carries
        // them WITHOUT a comprehension filter — which is what makes this rule possible at all. The
        // comparable set deliberately excludes an index whose expression did not arrive, and that is
        // the exact set this rule is about.
        foreach (ForeignKeyIndexCoverage::parse($object->getString('unique_indexes') ?? '') as $index => $keyPositions) {
            $keys = array_filter(array_map(CaseFoldedKey::parse(...), $keyPositions));

            if ($keys !== []) {
                $folded[(string) $index] = implode(' and ', array_map(
                    static fn (CaseFoldedKey $key): string => $key->describe(),
                    array_values($keys),
                ));
            }
        }

        ksort($folded);

        // One verdict for the table naming every index, not one per index: a catalog finding is
        // located at the object and results are deduplicated by rule id and location, so a second
        // would be dropped without a word.
        return $folded === [] ? [] : [RuleVerdict::flag($this->message($object, $folded))];
    }

    /** @param  non-empty-array<string, string>  $folded  index name => the folded keys it is unique over */
    private function message(SchemaObject $object, array $folded): string
    {
        $named = [];

        foreach ($folded as $index => $keys) {
            $named[] = $index.' is unique over '.$keys;
        }

        return sprintf(
            'On %s: %s. That is a guarantee about a folded value rather than about the column, so two rows '
            .'differing only in case cannot both exist — and a lookup comparing the column directly asks a '
            .'different question than the index answers. An existence check that finds nothing, followed by an '
            .'insert the index refuses, is the shape this produces: the caller is told the value is free and '
            .'the write then fails, and on an endpoint built not to disclose whether a record exists, the '
            .'difference between those two answers is the disclosure. Compare the way the index does, or fold '
            .'on the way in, so that both sides hold the same value. The index itself is not the problem and '
            .'dropping it would remove the guarantee rather than fix the mismatch.',
            $object->qualifiedName,
            implode('; ', $named),
        );
    }
}
