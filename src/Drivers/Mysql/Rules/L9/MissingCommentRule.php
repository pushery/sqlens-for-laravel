<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresConfigurationReach;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;
use Pushery\SQLens\Rules\Pedantic\MissingComment;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A table or column with no comment — the most opinionated check in the catalog, and OFF by default.
 *
 * ## Two opt-ins, not one, and the second is the important one
 *
 * Level 9 already keeps this out of an ordinary run. That is not enough: a project that raised its
 * level to see the pedantic band has asked to be shown opinionated findings, not to be told in the
 * same breath that every table it owns is undocumented. So the rule stays silent until
 * `audit.documentation.require_table_comments` (or its column twin) is turned on.
 *
 * The two switches are separate because they are different amounts of work. Documenting tables is
 * something a team can finish; requiring the same of every column is a decision of its own, and one
 * switch would have made the cheaper half unreachable.
 *
 * ## The framework tables are exempt by default, and that is not a courtesy
 *
 * Every Laravel application ships `migrations`, `jobs`, `cache`, `sessions` and the rest. None will
 * ever carry a comment and none should. Without the exemption this rule reports double digits on a
 * brand-new application — the fastest way to have it switched off along with everything near it.
 *
 * Extension-owned objects need no exemption here: the catalog reader already filters them out of
 * the object stream, and answering that question twice would be two answers to keep in step.
 *
 * ## Audit only
 *
 * MySQL puts a comment INLINE in the `CREATE TABLE`, so a lint run could read one off the statement
 * that creates a table. It still cannot answer the question, for the same reason as its PostgreSQL
 * sibling: a lint run sees the PENDING migrations, and a table documented two years ago carries its
 * comment in the catalog and in no pending migration. A lint half would report almost every table
 * in the schema as undocumented.
 */
final class MissingCommentRule extends AbstractCatalogRule implements DeclaresConfigurationReach, DeclaresJudgedObjectTypes
{
    /**
     * @param  DocumentationPolicy  $policy  what the project asked for, built once by the registry
     *                                       and handed down — a rule that read the configuration
     *                                       would have a verdict its own tests cannot see
     */
    private readonly DocumentationPolicy $policy;

    public function __construct(string $projectRoot = '', ?DocumentationPolicy $policy = null)
    {
        parent::__construct($projectRoot);

        $this->policy = $policy ?? DocumentationPolicy::shipped();
    }

    /**
     * Off unless the project turned one of the two switches on — the state this rule ships in.
     *
     * EITHER switch is enough to make it reachable, because the two are independent halves: a
     * project that requires table comments and not column ones still gets findings, and reporting
     * that rule as silenced would be wrong in the direction that matters least visibly.
     *
     * The phrase names the keys rather than describing the state, so the reader of a generated
     * context file can go and change one instead of going to look for it.
     */
    public function silencedByConfiguration(): ?string
    {
        if ($this->policy->requireTableComments || $this->policy->requireColumnComments) {
            return null;
        }

        return 'both `audit.documentation.require_table_comments` and `require_column_comments` are off';
    }

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table, SchemaObjectType::Column];
    }

    public function id(): string
    {
        return 'MY.L9.DOC_MISSING_COMMENT';
    }

    public function level(): Level
    {
        return Level::Pedantic;
    }

    public function category(): Category
    {
        return Category::Convention;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        // Stated as a guard rather than left to the match's default arm, and not only for the
        // reader: the declaration guard derives what a rule narrows to from its comparisons, and a
        // narrowing that lives only inside a match reads as narrower than it is.
        if ($object->type !== SchemaObjectType::Table && $object->type !== SchemaObjectType::Column) {
            return [];
        }

        $wanted = $object->type === SchemaObjectType::Table
            ? $this->policy->requireTableComments
            : $this->policy->requireColumnComments;

        if (! $wanted) {
            return [];
        }

        // A column is judged by the exemption of the TABLE that owns it, not by its own name.
        // Exempting `migrations` has to exempt `migrations.batch` too, or the table switch would be
        // honored and the column switch would report the framework anyway.
        $owner = $object->type === SchemaObjectType::Column
            ? $object->parent ?? $object->qualifiedName
            : $object->qualifiedName;

        if (in_array(MissingComment::bareName($owner), $this->policy->exempt, true)) {
            return [];
        }

        if (MissingComment::documented($object)) {
            return [];
        }

        if (! MissingComment::readable($object)) {
            // The reading never established anything about this object's comment. Reporting a
            // missing one would accuse a schema of something nobody measured.
            return [RuleVerdict::undetermined(
                'Whether `'.$object->qualifiedName.'` carries a comment was not established by this reading, so it '
                .'is unknown rather than missing.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        return [RuleVerdict::flag(
            '`'.$object->qualifiedName.'` carries no comment, and this project asked for one. '
            .'Add one with `COMMENT` on the table or column, or `->comment()` in the migration.',
            $object->qualifiedName,
            $object->type,
        )];
    }
}
