<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Pedantic\ImplicitCast;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A foreign key whose two ends are not the same type — and on MySQL that means something narrower
 * than it sounds.
 *
 * ## Half the pairs this rule could report cannot exist here
 *
 * MySQL 8.4.10 refuses an integer-width mismatch outright. Measured:
 *
 * ```
 * CREATE TABLE k1 (pid int, FOREIGN KEY (pid) REFERENCES p_big(id));   -- p_big.id is bigint
 * ERROR 3780 (HY000): Referencing column 'pid' and referenced column 'id'
 *                     in foreign key constraint 'k1_ibfk_1' are incompatible.
 * ```
 *
 * Signed or unsigned makes no difference — both are refused. So the case that motivates the
 * PostgreSQL sibling never reaches a MySQL catalog, and a rule that went looking for it here would
 * be a check that cannot fail.
 *
 * ## What DOES survive is the interesting half
 *
 * Also measured on 8.4.10, both created without complaint:
 *
 * ```
 * varchar(50)  referencing  varchar(100)   -- created. Same type, different length: no conversion.
 * timestamp    referencing  datetime       -- created. DIFFERENT types, converted on every compare.
 * ```
 *
 * The first is why the comparison is the BASE type and not the declared one: a length difference is
 * not a cast, and reporting it would fire on the most common shape in a real schema. The second is
 * exactly what this rule is for — a pair MySQL accepted and converts at runtime, on a join the
 * application runs constantly.
 *
 * ## Audit only, for the same structural reason as its sibling
 *
 * A migration adding a foreign key carries the type of neither column, and the referenced table was
 * created by a migration that is no longer pending. The catalog is where both ends exist at once.
 */
final class TypeImplicitCastRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Empty, and that is a measurement rather than an omission.
     *
     * PostgreSQL has a genuinely free pair — `text` and `varchar` share storage. MySQL has no
     * equivalent: `varchar` and `char` differ in padding, `text` differs from both in storage and in
     * index handling. Every group added here silences a real finding, so the list stays empty until
     * a pair is shown to cost nothing.
     *
     * @var list<list<string>>
     */
    private const array EQUIVALENT = [];

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'MY.L9.TYPE_IMPLICIT_CAST';
    }

    public function level(): Level
    {
        return Level::Pedantic;
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

        $offenders = [];
        $unread = [];

        foreach (ImplicitCast::pairs($object) as $pair) {
            if ($pair['localType'] === null || $pair['farType'] === null) {
                $unread[] = $pair['constraint'].' ('.$pair['local'].' → '.$pair['far'].')';

                continue;
            }

            if (ImplicitCast::sameType($pair['localType'], $pair['farType'], self::EQUIVALENT)) {
                continue;
            }

            $offenders[] = sprintf(
                '`%s` is `%s` and references `%s`, which is `%s`. MySQL accepted the key and converts one side on '
                .'every comparison — on a join the application runs constantly, and on a conversion the schema '
                .'never asked for. Declare both ends as the same type.',
                $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
            );
        }

        if ($offenders !== []) {
            sort($offenders, SORT_STRING);

            return [RuleVerdict::flag(implode(' ', $offenders), $object->qualifiedName, $object->type)];
        }

        if ($unread !== []) {
            sort($unread, SORT_STRING);

            return [RuleVerdict::undetermined(
                'The type of at least one end of these foreign keys was not established, so whether the two sides '
                .'agree is unknown rather than fine: '.implode(', ', $unread).'.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        return [];
    }
}
