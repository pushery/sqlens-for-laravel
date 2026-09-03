<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The database object a `dblint` diagnostic is about, recovered from its message.
 *
 * ## Why it is parsed at all
 *
 * The tool's diagnostics carry no file and no line — measured: three fields, `severity`, `message`
 * and `category`, and nothing else. It judges a schema rather than a document, so there is nothing
 * for a position to point at and the package's position mapper does not apply. The only identity
 * available is the object the message names, so that is what this reads.
 *
 * ## Why an unreadable message is not a failure
 *
 * Exactly ONE message shape was measured, because a plain database produces exactly one finding:
 *
 * ```text
 * Function \`public.f\` has a role mutable search_path
 * ```
 *
 * Note the backslashes. They are literally in the JSON — the tool's SQL-level escaping leaks into
 * its report — and a parser written from the rendered text rather than the bytes would miss every
 * message. That is measured, not defensive.
 *
 * The other five rules in the catalog have message shapes nobody here has seen. So a message this
 * cannot read yields NULL, and the caller reports the finding anyway with no object named. The
 * alternative — guessing an object out of an unfamiliar sentence — would attach a real finding to
 * the wrong table, which is worse than attaching it to none: a reader can act on "somewhere in
 * this database", and cannot act on a confident lie.
 */
final readonly class PglsObjectReference
{
    /**
     * The nouns the tool opens a message with, mapped onto this package's object vocabulary.
     *
     * A closed list rather than a lower-cased lookup of whatever word appears first: an unknown
     * noun has to fall through to "no object named", and a permissive parser cannot do that — it
     * would take the first capitalized word of any sentence and call it a type.
     */
    private const array NOUNS = [
        'Table' => SchemaObjectType::Table,
        'View' => SchemaObjectType::View,
        'Materialized view' => SchemaObjectType::MaterializedView,
        'Function' => SchemaObjectType::Routine,
        'Extension' => SchemaObjectType::Type,
        'Policy' => SchemaObjectType::Policy,
        'Column' => SchemaObjectType::Column,
        'Sequence' => SchemaObjectType::Sequence,
        'Schema' => SchemaObjectType::Schema,
    ];

    /**
     * `Noun \`qualified.name\`` at the very start of the message, and nowhere else.
     *
     * Anchored at the start deliberately. A backticked name appearing mid-sentence is something
     * the message MENTIONS — a schema it recommends, a setting it names — not the object the
     * finding is about, and reading it as the subject would file the finding against a bystander.
     */
    private const string LEADING_OBJECT = '/^(?<noun>[A-Z][a-z]+(?: [a-z]+)?) \\\\?`(?<name>[^`\\\\]+)\\\\?`/';

    private function __construct(
        public SchemaObjectType $type,
        /** As the tool wrote it, e.g. `public.f` — schema-qualified when the tool qualified it. */
        public string $name,
    ) {}

    /** The object the message is about, or null when this build cannot tell. */
    public static function fromMessage(string $message): ?self
    {
        if (preg_match(self::LEADING_OBJECT, $message, $matches) !== 1) {
            return null;
        }

        $type = self::NOUNS[$matches['noun']] ?? null;

        if (! $type instanceof SchemaObjectType) {
            return null;
        }

        $name = trim($matches['name']);

        return $name === '' ? null : new self($type, $name);
    }
}
