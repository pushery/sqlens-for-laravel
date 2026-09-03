<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

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
 * A `json` column where `jsonb` is almost always meant.
 *
 * ## The difference is not cosmetic
 *
 * `json` stores the document as TEXT, exactly as it arrived. Every read that looks inside it —
 * every `->>`, every containment test, every path expression — re-parses the whole value first.
 * `jsonb` stores a decomposed binary form: it parses once, on write.
 *
 * The consequence that actually decides projects is indexing. A GIN index over `jsonb` answers
 * containment (`@>`) and key-existence questions directly; `json` has no such operator class, so
 * those queries have no index to use at all and read every row. A column that grows past a few
 * thousand rows and is ever filtered on will feel the difference, and no amount of query tuning
 * recovers it while the type stays `json`.
 *
 * ## The one legitimate reason to keep `json`, stated rather than dismissed
 *
 * `jsonb` does not preserve the document as written. It drops insignificant whitespace, it does not
 * keep key ORDER, and it keeps only the LAST of duplicate keys. `json` keeps all three, byte for
 * byte.
 *
 * That matters when the stored document is evidence rather than data: a signed webhook payload
 * whose signature is computed over the exact bytes, an audit record that must round-trip
 * unmodified, an API response kept for a dispute. Re-serializing those from `jsonb` produces a
 * different document, and for a signature check that means a mismatch.
 *
 * So this rule recommends and does not insist. It is level 6, its message names the exception, and
 * a project that keeps `json` on purpose ignores it deliberately — which leaves the decision in the
 * report rather than losing it.
 *
 * ## What it cannot see
 *
 * A column typed as a DOMAIN over `json` reads as the domain's name in the catalog, not as `json`,
 * so this rule does not report it. Naming what it misses is the honest form: a rule that quietly
 * covered part of its subject would leave a reader believing the whole of it was checked.
 */
final class JsonNotJsonbRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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
        return 'PG.L6.JSON_NOT_JSONB';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Idiom;
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
            if (strtolower($types[0] ?? '') === 'json') {
                $columns[] = (string) $column;
            }
        }

        sort($columns);

        // One verdict for the table naming every column, not one per column: a catalog finding is
        // located at the object, and results are deduplicated by rule id and location — so the
        // second and third would be dropped without a word. It is also the better report, because
        // converting them is one decision about one table.
        return $columns === [] ? [] : [RuleVerdict::flag($this->message($object, $columns))];
    }

    /** @param  list<string>  $columns */
    private function message(SchemaObject $object, array $columns): string
    {
        return sprintf(
            'On %s: %s %s of type json, which stores the document as text and re-parses it on every read that '
            .'looks inside. jsonb parses once, on write — and it is the one of the two that can be indexed: a '
            .'GIN index answers containment and key-existence directly, while json has no operator class for '
            .'them and every such query reads the whole table. Keep json only where the exact bytes matter: it '
            .'preserves key order, duplicate keys and whitespace, and jsonb preserves none of the three — so a '
            .'signed webhook payload or an audit record that has to round-trip unmodified is a real reason to '
            .'stay, and ordinary application data is not.',
            $object->qualifiedName,
            implode(', ', $columns),
            count($columns) === 1 ? 'is' : 'are',
        );
    }
}
