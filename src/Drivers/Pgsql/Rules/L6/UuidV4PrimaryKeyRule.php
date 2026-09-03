<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\VersionWindow;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A random UUID primary key, where PostgreSQL 18 offers a time-ordered one.
 *
 * ## What the cost actually is
 *
 * A v4 UUID is random, so consecutive inserts land in unrelated places in the primary key's B-tree.
 * Every insert dirties a different page, the pages that matter stop fitting in cache, and the index
 * splits far more than a sequential key would. None of it is a correctness problem and none of it
 * shows up on a small table — which is exactly why it is level 6 and an idiom rather than a
 * failure. It is a recommendation about appetite, and it says so.
 *
 * `uuidv7()` arrived in PostgreSQL 18. The values keep the uniqueness properties a UUID is chosen
 * for while sorting by creation time, so inserts land at the end of the index the way a sequence
 * would.
 *
 * ## Why it is gated, and gated hard
 *
 * On PostgreSQL 17 the function does not exist. A recommendation to use it there is not merely
 * premature — it is advice that cannot be followed, and advice that cannot be followed is how a
 * tool teaches people to skim its output. The window is declared rather than checked in the message,
 * so the rule is not applied at all below 18 and the report says it was withheld.
 *
 * ## The trade-off the recommendation carries
 *
 * A v7 UUID encodes the moment it was created. Where the identifier is public — in a URL, in an API
 * response — it tells anybody holding it when the row was created, which a v4 does not. That is a
 * real reason to keep v4, and the documentation says so rather than preaching v7. This rule
 * recommends; it does not know your threat model.
 *
 * ## Three values, and the middle one is the common case
 *
 * A UUID column with no server-side default tells this rule nothing on its own. Laravel generates
 * UUIDs in the application, so an absent default is the ordinary shape rather than a signal, and
 * whether the values are v4 or v7 is a fact about code this rule never reads. It answers
 * `undetermined` with a named reason and points at the one config key that resolves it — instead of
 * either guessing or staying silent, which would look identical to a clean table.
 */
final class UuidV4PrimaryKeyRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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

    /**
     * The generators that produce a random value.
     *
     * `gen_random_uuid()` is core; `uuid_generate_v4()` comes from the uuid-ossp extension and is
     * still widely installed. Both are named because a project that migrated from the extension to
     * core, or never did, is judged the same way.
     *
     * @var list<string>
     */
    private const array RANDOM_GENERATORS = ['gen_random_uuid', 'uuid_generate_v4'];

    /** The time-ordered generator PostgreSQL 18 introduced. */
    private const string SORTED_GENERATOR = 'uuidv7';

    /**
     * @param  string|null  $generatedBy  what the project declared about who produces the value —
     *                                    `app`, `server`, or null when it has not said
     */
    public function __construct(string $projectRoot, private readonly ?string $generatedBy = null)
    {
        parent::__construct($projectRoot);
    }

    public function id(): string
    {
        return 'PG.L6.PK_UUID_V4';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    /**
     * Idiom, not performance, and the level is why.
     *
     * The harm is a performance one, but level 6 is the band a project opts into for
     * recommendations about shape. Filed under performance it would sit beside findings a team
     * gates a deploy on, and a recommendation that blocks a deploy is one somebody switches off.
     */
    public function category(): Category
    {
        return Category::Idiom;
    }

    /** PostgreSQL 18 and up: below it, `uuidv7()` does not exist and the advice cannot be taken. */
    #[Override]
    public function versionWindow(): VersionWindow
    {
        return VersionWindow::from(ServerVersion::of(18, 0, 0, 'pgsql'));
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

        $column = $this->singleUuidPrimaryKeyColumn($object);

        if ($column === null) {
            return [];
        }

        $generator = $this->defaultGenerator($object, $column);

        if ($generator === self::SORTED_GENERATOR) {
            return [];
        }

        if ($generator !== null && in_array($generator, self::RANDOM_GENERATORS, true)) {
            return [RuleVerdict::flag($this->serverSideMessage($object, $column, $generator))];
        }

        // A default this rule does not recognize — `nextval` on a uuid column, a custom function,
        // a literal. It is not random and it is not v7, and inventing a verdict for it would be a
        // guess about somebody's own generator.
        if ($generator !== null) {
            return [];
        }

        return [$this->withoutServerDefault($object, $column)];
    }

    /**
     * The single-column UUID primary key, or null when the table has none.
     *
     * Single-column on purpose. A composite key's leading column decides the insert position, but a
     * composite UUID key is rare enough that a recommendation about it would rest on a shape nobody
     * here has measured — and a rule that reasons about a shape it has not seen is how confident
     * wrong advice ships.
     */
    private function singleUuidPrimaryKeyColumn(SchemaObject $object): ?string
    {
        $primary = ForeignKeyIndexCoverage::parse($object->getString('primary_key') ?? '');
        $columns = array_values($primary)[0] ?? [];

        if (count($columns) !== 1) {
            return null;
        }

        $column = $columns[0];
        $types = ForeignKeyIndexCoverage::parse($object->getString('column_types') ?? '');
        $type = $types[$column][0] ?? null;

        return $type !== null && strtolower($type) === 'uuid' ? $column : null;
    }

    /** The function this column's default calls, or null when it has none this reading could name. */
    private function defaultGenerator(SchemaObject $object, string $column): ?string
    {
        $defaults = ForeignKeyIndexCoverage::parse($object->getString('column_default_functions') ?? '');

        return $defaults[$column][0] ?? null;
    }

    /**
     * No server-side default: the answer depends on what the project says about its own code.
     *
     * Declaring `server` does NOT conjure a default the catalog did not show. The two disagree in
     * that case, and the honest answer is still that this rule cannot see which generator runs —
     * saying otherwise would resolve a contradiction by picking the side that was easier to state.
     */
    private function withoutServerDefault(SchemaObject $object, string $column): RuleVerdict
    {
        if ($this->generatedBy === 'app') {
            return RuleVerdict::flag(sprintf(
                '%s.%s is a UUID primary key generated by the application. PostgreSQL 18 offers time-ordered '
                .'UUIDs, and generating v7 values application-side gives the same insert locality: consecutive '
                .'rows land together in the primary key rather than scattering across it. Nothing here is '
                .'broken — this is a recommendation about write behavior on a table that grows. Note the '
                .'trade-off before taking it: a v7 value encodes when it was created, so a public identifier '
                .'reveals the row\'s age.',
                $object->qualifiedName,
                $column,
            ));
        }

        return RuleVerdict::undetermined(
            sprintf(
                '%s.%s is a UUID primary key with no server-side default, so whether its values are random or '
                .'time-ordered depends on code this audit does not read. That is the ordinary shape for a '
                .'Laravel application, not a fault. Set sqlens.audit.uuid_generated_by to "app" or "server" to '
                .'have this answered.',
                $object->qualifiedName,
                $column,
            ),
            UndeterminedReason::UuidGenerationUnknown,
        );
    }

    private function serverSideMessage(SchemaObject $object, string $column, string $generator): string
    {
        return sprintf(
            '%s.%s is a UUID primary key defaulting to %s(), which produces a random value. Consecutive inserts '
            .'therefore land in unrelated places in the primary key\'s B-tree: every insert dirties a different '
            .'page, the hot pages stop fitting in cache, and the index splits more than a sequential key would. '
            .'PostgreSQL 18 offers uuidv7(), which keeps the uniqueness a UUID is chosen for while sorting by '
            .'creation time. Nothing here is broken — this is a recommendation about write behavior on a table '
            .'that grows. Note the trade-off before taking it: a v7 value encodes when it was created, so a '
            .'public identifier reveals the row\'s age.',
            $object->qualifiedName,
            $column,
            $generator,
        );
    }
}
