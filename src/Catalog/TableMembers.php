<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Catalog\Understanding\IndexComprehension;
use Pushery\SQLens\Catalog\Understanding\IndexPredicate;
use Pushery\SQLens\Rules\Indexes\RedundantIndex;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Gives a table the members a rule has to see ALONGSIDE it — the shape every L5–7 rule reads.
 *
 * ## The problem this solves, stated plainly
 *
 * A rule evaluates one `Subject`. But the questions the level 5–7 rules ask are about a table
 * AND its parts at once: "is this foreign key covered by an index" needs the key's columns and the
 * table's indexes together, and a constraint object does not know its siblings. Three ways out
 * existed, and two of them were worse:
 *
 * - Give the CONSTRAINT a `covered` flag. Shortest, and wrong: "is this foreign key covered" IS the
 *   rule. Computed in the reader, the rule becomes a boolean lookup and the predicate/operator-class
 *   caution that makes the answer trustworthy ends up in a layer that knows nothing about rules.
 * - Hand the rule the whole snapshot. Breaks the subject contract for every other rule to fix one.
 * - **Give the TABLE its members as facts.** The reader keeps reporting only what it read; the rule
 *   keeps doing all the judging. That is this class.
 *
 * ## Why comparable indexes are listed SEPARATELY
 *
 * A partial index, an expression index and one with a non-default operator class are all real
 * indexes and all belong in `indexes`. None of them covers a foreign key, and a rule that treated
 * them as coverage would stay silent about a table that scans on every parent delete — the exact
 * false NEGATIVE this package's caution is aimed at. So `comparable_indexes` holds only what
 * {@see IndexComprehension} already judged comparable AND what the server would actually use, and a
 * rule that wants coverage reads that one. Both are present, so a rule can also say "there IS an
 * index here, it just is not one I can reason about" instead of implying none exists.
 *
 * ## The encoding
 *
 * `name(col, col); name(col)` — sorted, so two readings diff cleanly. Attributes are scalar by
 * design (a snapshot has to serialize to stable JSON), and the same shape already carries a
 * partition list, so this is the house form rather than a new one. Plain column lists use the same
 * separator without the parentheses, because a column has no members of its own.
 *
 * ## Why the key facts are FOUR attributes and not one flag
 *
 * "Is this table adequately keyed?" is a rule's question, not a reader's, and answering it here
 * would put the judgment in the layer that must only report. So the reading contributes the facts
 * it can stand behind, each separately:
 *
 * - `primary_key` — the primary key's own entry, empty when there is none.
 * - `unique_indexes` — the unique indexes that are NOT the primary key. Both engines list the
 *   primary key as unique as well, and folding them together would make "a unique key but no
 *   primary key" — the case where a substitute identity is even possible — unaskable.
 * - `column_types` and `column_default_functions` — what a column IS and what it defaults to
 *   calling. Both are projections, not copies: the type is the canonical one, and only a
 *   zero-argument function default travels, because the `name(value)` encoding cannot carry a
 *   value with parentheses of its own. A rule needing more than that needs the column object.
 * - `column_charsets` and `column_collations` — what a column stores characters in, and what it
 *   sorts them by. Two attributes rather than one, because they are two decisions: a schema can be
 *   on `utf8mb4` throughout and still sort by a collation from before MySQL 8.0. Only columns that
 *   HAVE one appear, so a column present in `columns` and absent here holds no characters at all —
 *   an `int`, a `blob` — which a rule must not confuse with one whose encoding went unread.
 * - `payload_indexes` — the indexes carrying an INCLUDE payload beyond their key columns. Without
 *   it `(a) INCLUDE (b)` and `(a)` are indistinguishable, and a redundancy rule would recommend
 *   dropping the more useful of the two. See {@see self::withPayload()}.
 * - `same_predicate_indexes` and `index_predicate_groups` — the partial indexes that share a
 *   condition with another partial index on the same table, and the group token each one is in. Two
 *   attributes rather than one because the encoding is flat `name(cols)` and a predicate would not
 *   survive it; and because they answer two questions — which indexes, and which of them belong
 *   together. An index absent from both is either unconditional, or alone under its condition, or
 *   carries a predicate shape the reading refuses. See {@see self::samePredicate()}.
 * - `same_method_indexes` and `index_method_groups` — the same pair one attribute along, for the
 *   indexes whose ACCESS METHOD is what kept them out of `comparable_indexes`: a GIN, a GiST, a
 *   FULLTEXT. Grouped by method AND operator class, because inside one of those both cancel the way
 *   a shared predicate does. ⚠️ What may be concluded inside such a group is WEAKER than inside a
 *   predicate group — identity only, never a prefix — and that belongs to the rule rather than to
 *   this projection; see {@see RedundantIndex}. See {@see self::accessMethodKey()}.
 * - `unique_null_treatment` — whether each unique index counts two NULLs as the same value. Three-
 *   valued by construction: an index absent from the list had the flag unread, which a rule must not
 *   confuse with either answer. See {@see self::nullTreatment()}.
 * - `foreign_key_collations` — the one fact here that is NOT the table's own: each foreign key's
 *   text columns paired with the columns they point at, on other tables, both collations named. See
 *   {@see self::edges()} for why a table has to be handed it and what an omission means.
 * - `columns` and `nullable_columns` — a column missing from the first was never read, which is a
 *   different answer from being read and nullable. Whether a unique index can stand in for a
 *   primary key turns on its columns being NOT NULL, so a rule that could not tell "nullable" from
 *   "unknown" would have to guess in exactly the case that decides the finding.
 */
final readonly class TableMembers
{
    /** The object kinds that own members worth carrying — the ones a table-level rule reasons about. */
    private const array TABLE_LIKE = [
        SchemaObjectType::Table,
        SchemaObjectType::View,
        SchemaObjectType::MaterializedView,
    ];

    /**
     * Whether a rule may treat this index as covering a lookup — two exclusions, one list.
     *
     * The first is COMPREHENSION: a partial, expression or non-default-operator-class index was
     * read completely but its shape cannot be compared against a column list, so
     * {@see IndexComprehension} marks it not understood.
     *
     * The second is VALIDITY, and it was missing until a real reading exposed it. PostgreSQL leaves
     * an `indisvalid = false` index behind when a `CREATE INDEX CONCURRENTLY` is canceled or hits
     * a violation: a complete, ordinary-looking catalog row on exactly the right columns, which the
     * planner then IGNORES for queries because it may be incomplete. Counting one as coverage is
     * the worst shape of error available here — the check would report a table as fine while every
     * referential action on it still scans, and the index it pointed at would look right to anyone
     * verifying by hand.
     *
     * A missing `valid` attribute is treated as valid, because on MySQL the concept does not exist:
     * an engine with no invalid indexes must not have every index excluded by a flag it never sets.
     */
    private static function mayBeReasonedAboutAsCoverage(SchemaObject $index): bool
    {
        return $index->isFullyUnderstood() && $index->getBool('valid') !== false;
    }

    /**
     * Every table with its foreign keys and indexes attached; everything else untouched.
     *
     * @param  list<SchemaObject>  $objects
     * @return list<SchemaObject>
     */
    public static function attachTo(array $objects): array
    {
        $columns = [];
        $nullable = [];
        $types = [];
        $defaultFunctions = [];
        $charsets = [];
        $collations = [];
        $columnCollation = [];
        $columnType = [];
        $foreignKeyEdges = [];
        $spelling = [];
        $identity = [];
        $ownedSequences = [];
        $sequenceDefaults = [];

        /** @var array{fk: array<string, list<SchemaObject>>, index: array<string, list<SchemaObject>>, primary: array<string, list<SchemaObject>>, unique: array<string, list<SchemaObject>>, comparable: array<string, list<SchemaObject>>, partial: array<string, list<SchemaObject>>, exotic: array<string, list<SchemaObject>>} $members */
        $members = ['fk' => [], 'index' => [], 'primary' => [], 'unique' => [], 'comparable' => [], 'partial' => [], 'exotic' => []];

        /** @var array<string, string> $predicates index qualified name => its normalized predicate */
        $predicates = [];

        /** @var array<string, string> $accessMethods index qualified name => its method and class */
        $accessMethods = [];

        foreach ($objects as $object) {
            $parent = $object->parent ?? '';

            if ($object->type === SchemaObjectType::Column) {
                // Columns carry no key_columns, so they take their own path. Both lists are
                // attached rather than one: a column ABSENT from `columns` was never read, and
                // that is a different answer from "read, and nullable". A rule that collapsed the
                // two would treat a gap in the reading as a fact about the schema.
                $columns[$parent][] = self::shortName($object);
                // The vocabulary every member entry is rewritten INTO. See self::spell().
                $key = self::spellingKey(self::shortName($object));
                $spelling[$parent][$key] = array_key_exists($key, $spelling[$parent] ?? [])
                    ? null
                    : self::shortName($object);

                if ($object->getBool('not_null') === false) {
                    $nullable[$parent][] = self::shortName($object);
                }

                $type = $object->getString('type');

                if ($type !== null && $type !== '') {
                    $types[$parent][] = self::shortName($object).'('.$type.')';
                    // The same fact keyed by the column's own QUALIFIED name, so an edge landing on
                    // another table can be answered in the second pass — exactly as the collation
                    // map beside it does, and for the same reason: a per-table map would need the
                    // caller to know how each engine qualifies a column.
                    $columnType[$object->qualifiedName] = $type;
                }

                $function = self::defaultFunction($object->getString('default'));

                if ($function !== null) {
                    $defaultFunctions[$parent][] = self::shortName($object).'('.$function.')';
                }

                $identityKind = self::identityKind($object->getString('identity'));

                if ($identityKind !== null) {
                    $identity[$parent][] = self::shortName($object).'('.$identityKind.')';
                }

                $ownedSequence = $object->getString('owned_sequence');

                if ($ownedSequence !== null && $ownedSequence !== '') {
                    $ownedSequences[$parent][] = self::shortName($object).'('.$ownedSequence.')';
                }

                $sequenceShape = self::sequenceDefaultShape($object->getString('default'));

                if ($sequenceShape !== null) {
                    $sequenceDefaults[$parent][] = self::shortName($object).'('.$sequenceShape.')';
                }

                $charset = $object->getString('charset');

                if ($charset !== null && $charset !== '') {
                    $charsets[$parent][] = self::shortName($object).'('.$charset.')';
                }

                $collation = $object->getString('collation');

                if ($collation !== null && $collation !== '') {
                    $collations[$parent][] = self::shortName($object).'('.$collation.')';
                    // Keyed by the column's own qualified name, so an edge landing on ANOTHER table
                    // can be answered in the second pass. A per-table map would need the caller to
                    // know how each engine qualifies a column; this needs nothing.
                    $columnCollation[$object->qualifiedName] = $collation;
                }

                continue;
            }

            // A member without columns is left out here rather than encoded as `name()`: an empty
            // column list is not a fact about the object, it is the absence of one, and a rule
            // matching prefixes against it would match everything.
            if (trim($object->getString('key_columns') ?? '') === '') {
                continue;
            }

            // Collected, NOT encoded. Encoding rewrites each column into the spelling its column
            // object carries, and that map is only complete once every column has been seen.
            if ($object->type === SchemaObjectType::Constraint && self::isForeignKey($object)) {
                $members['fk'][$parent][] = $object;
                // Both ends of an edge have to be known before it can be described, and the far end
                // may be a table this loop has not reached yet.
                $foreignKeyEdges[] = $object;

                continue;
            }

            if ($object->type === SchemaObjectType::Index) {
                $members['index'][$parent][] = $object;

                if ($object->getBool('primary') === true) {
                    $members['primary'][$parent][] = $object;
                } elseif ($object->getBool('unique') === true) {
                    // The primary key is a unique index too, on both engines. Listing it in both
                    // places would make "has a unique key but no primary key" — the question the
                    // substitute-identity rule turns on — impossible to ask.
                    $members['unique'][$parent][] = $object;
                }

                if (self::mayBeReasonedAboutAsCoverage($object)) {
                    $members['comparable'][$parent][] = $object;
                }

                // A partial index never joins `comparable` — it does not cover a lookup that the
                // predicate excludes, and a foreign-key check counting one would report a table as
                // indexed while every referential action on it still scans. It is collected here
                // instead, under its NORMALIZED predicate, for the one comparison that survives
                // without implication: see {@see self::samePredicate()}.
                $reading = self::partialPredicate($object);

                if ($reading !== null) {
                    $members['partial'][$parent][] = $object;
                    $predicates[$object->qualifiedName] = $reading;
                }

                // An index whose ACCESS METHOD is what kept it out of `comparable` — a GIN, a GiST,
                // a FULLTEXT. Same move as the line above, one attribute along: it is collected
                // under the method it shares, for the one comparison that needs no knowledge of how
                // that method searches. See {@see self::accessMethodKey()}.
                $methodKey = self::accessMethodKey($object);

                if ($methodKey !== null) {
                    $members['exotic'][$parent][] = $object;
                    $accessMethods[$object->qualifiedName] = $methodKey;
                }
            }
        }

        $nullTreatment = self::nullTreatment($members['unique']);
        $payload = self::encodeMembers(self::withPayload($members['index']), $spelling);
        $foreignKeys = self::encodeMembers($members['fk'], $spelling);
        $indexes = self::encodeMembers($members['index'], $spelling);
        $primary = self::encodeMembers($members['primary'], $spelling);
        $unique = self::encodeMembers($members['unique'], $spelling);
        $comparable = self::encodeMembers($members['comparable'], $spelling);
        $sharedPredicate = self::samePredicate($members['partial'], $predicates);
        $samePredicateIndexes = self::encodeMembers($sharedPredicate['indexes'], $spelling);
        $sharedMethod = self::universesBy($members['exotic'], $accessMethods);
        $sameMethodIndexes = self::encodeMembers($sharedMethod['indexes'], $spelling);

        $edges = self::edges($foreignKeyEdges, $columnCollation, $spelling, skipUnknownLocal: true);
        // The same edges over TYPES, and the one flag between them is load-bearing. A column
        // with no collation holds no text, so no collation comparison can happen on it and the
        // pair is correctly absent. A column with no READ TYPE is a different thing entirely —
        // every column has one — so dropping it would turn an unread column into a silent pass
        // on exactly the question the type rule asks.
        $typeEdges = self::edges($foreignKeyEdges, $columnType, $spelling, skipUnknownLocal: false);
        $attached = [];

        foreach ($objects as $object) {
            if (! in_array($object->type, self::TABLE_LIKE, true)) {
                $attached[] = $object;

                continue;
            }

            $name = $object->qualifiedName;

            $attached[] = $object->withAttributes([
                'foreign_keys' => self::encode($foreignKeys[$name] ?? []),
                'indexes' => self::encode($indexes[$name] ?? []),
                'comparable_indexes' => self::encode($comparable[$name] ?? []),
                'primary_key' => self::encode($primary[$name] ?? []),
                'unique_indexes' => self::encode($unique[$name] ?? []),
                'columns' => self::encode($columns[$name] ?? []),
                'nullable_columns' => self::encode($nullable[$name] ?? []),
                'column_types' => self::encode($types[$name] ?? []),
                'column_default_functions' => self::encode($defaultFunctions[$name] ?? []),
                'column_charsets' => self::encode($charsets[$name] ?? []),
                'column_collations' => self::encode($collations[$name] ?? []),
                'foreign_key_collations' => self::encode($edges[$name] ?? []),
                'foreign_key_types' => self::encode($typeEdges[$name] ?? []),
                'unique_null_treatment' => self::encode($nullTreatment[$name] ?? []),
                'payload_indexes' => self::encode($payload[$name] ?? []),
                'same_predicate_indexes' => self::encode($samePredicateIndexes[$name] ?? []),
                'index_predicate_groups' => self::encode($sharedPredicate['groups'][$name] ?? []),
                'same_method_indexes' => self::encode($sameMethodIndexes[$name] ?? []),
                'index_method_groups' => self::encode($sharedMethod['groups'][$name] ?? []),
                'identity_columns' => self::encode($identity[$name] ?? []),
                'sequence_owned_columns' => self::encode($ownedSequences[$name] ?? []),
                'sequence_default_columns' => self::encode($sequenceDefaults[$name] ?? []),
            ]);
        }

        return $attached;
    }

    /**
     * Each foreign key's text columns paired with the columns they point at, both collations named.
     *
     * ## The one fact a table cannot hold about itself
     *
     * Everything else here is a table's own members. This is not: the far end of a foreign key lives
     * on ANOTHER table, and a rule judges one object at a time. Two columns compared across a
     * collation boundary force MySQL to convert one side at runtime, and the converted side stops
     * being able to use its index — the join the application runs constantly turns into a scan. That
     * question is unaskable without both ends, so the reading answers it here and the rule still
     * does all the judging.
     *
     * ## The encoding, and what an omission means
     *
     * `constraint#n(local=collation, other.table.column=collation)` — one entry per column POSITION,
     * because a composite key pairs position with position and pairing by name would be wrong the
     * moment the two sides spell a column differently.
     *
     * A missing `=collation` on the far side means the edge could not be followed: the referenced
     * table lies outside the audited scope, or its columns were not read. That is deliberately
     * distinguishable from a resolved edge, because "the far side is fine" and "nobody looked at the
     * far side" must not read the same — the whole point of the third value.
     *
     * A pair whose LOCAL column has no collation does not appear at all: it holds no text, so no
     * comparison across collations can happen on it. A local column that was never read produces the
     * same absence, and that conflation is deliberate — a reading that lost columns is already
     * reported as a catalog skip, and a second report of it per foreign key would bury the first.
     *
     * ## It used to be EMPTY on PostgreSQL. It is not any more
     *
     * This paragraph said the PostgreSQL reader recorded no referenced table, so no edge was
     * described there, and that a future rule would have to make the reader produce the fact first.
     * That has happened: `PgsqlCatalogReader` now reads `confrelid` and `confkey`, so edges are
     * described on both engines.
     *
     * The sentence is replaced rather than deleted, because the warning it carried still holds and
     * is the reason the projection is shaped this way: an EMPTY projection must never be read as
     * "no mismatch". It means nobody looked.
     *
     * ## One builder, two facts, one flag
     *
     * Collations and types travel through the same edges — same pairing by position, same encoding,
     * same meaning for a missing far side. What differs is what an UNKNOWN LOCAL value means, and it
     * differs completely: a column with no collation holds no text, so no collation comparison can
     * happen on it and the pair belongs absent. Every column has a type, so a missing one means the
     * reading lost it — and dropping that pair would answer the type question with silence, which a
     * rule reads as agreement.
     *
     * @param  list<SchemaObject>  $constraints  the foreign keys, in reading order
     * @param  array<string, string>  $columnFact  column qualified name => the fact being paired
     * @param  array<string, array<string, string|null>>  $spelling  table => the map {@see self::spell()} uses
     * @param  bool  $skipUnknownLocal  true when an absent local fact means the pair is inapplicable
     * @return array<string, list<string>> table => its encoded edges
     */
    private static function edges(array $constraints, array $columnFact, array $spelling, bool $skipUnknownLocal): array
    {
        $edges = [];

        foreach ($constraints as $constraint) {
            $table = $constraint->parent ?? '';
            $referenced = $constraint->getString('referenced_relation');
            // Spelled through the same map as every other member: this list is looked up against
            // column objects on BOTH tables, so a raw name would miss on a quoted schema exactly
            // the way an index's would.
            $local = self::columnList($constraint->getString('key_columns'), $spelling[$table] ?? []);
            $far = self::columnList($constraint->getString('referenced_columns'), $spelling[$referenced ?? ''] ?? []);

            // A constraint that names no target is not an edge anybody can follow — a check
            // constraint on this engine, or a foreign key whose target the server did not qualify.
            if ($referenced === null) {
                continue;
            }

            // Two sides that do not line up describe different things, and encoding them
            // half-resolved would invite a rule to compare position 0 against position 0 of lists
            // that are not about the same columns.
            if (count($local) !== count($far)) {
                continue;
            }

            foreach ($local as $position => $column) {
                $value = $columnFact[$table.'.'.$column] ?? null;

                if ($value === null && $skipUnknownLocal) {
                    continue;
                }

                $farName = $referenced.'.'.$far[$position];
                $farValue = $columnFact[$farName] ?? null;

                $edges[$table][] = sprintf(
                    '%s#%d(%s, %s)',
                    self::shortName($constraint),
                    $position,
                    // A bare name on either side means the fact was not read for it. Symmetric on
                    // purpose: a rule comparing two sides has to be able to tell "they differ" from
                    // "one of them is unknown", and the second is undetermined rather than a finding.
                    $value === null ? $column : $column.'='.$value,
                    $farValue === null ? $farName : $farName.'='.$farValue,
                );
            }
        }

        return $edges;
    }

    /**
     * A `col, col` list as an ordered array, each name spelled the way its column object spells it.
     *
     * @param  array<string, string|null>  $spelling
     * @return list<string>
     */
    private static function columnList(?string $encoded, array $spelling): array
    {
        if ($encoded === null || trim($encoded) === '') {
            return [];
        }

        $names = array_filter(array_map(trim(...), explode(',', $encoded)), static fn (string $c): bool => $c !== '');

        return array_values(array_map(static fn (string $c): string => self::spell($c, $spelling), $names));
    }

    /**
     * How a column gets its value from the engine itself: `always`, `by_default`, or not at all.
     *
     * PostgreSQL spells this in one character — `a` for GENERATED ALWAYS, `d` for GENERATED BY
     * DEFAULT, empty for neither — and `information_schema` flattens the two into one YES. They are
     * kept apart because they answer different questions: ALWAYS refuses an explicit insert, BY
     * DEFAULT accepts one, and a rule about migrating off `serial` has to say which one it means.
     */
    private static function identityKind(?string $identity): ?string
    {
        return match ($identity) {
            'a' => 'always',
            'd' => 'by_default',
            default => null,
        };
    }

    /**
     * Whether a default draws from a sequence, and whether it does so in the shape `serial` makes.
     *
     * ## Why the SHAPE and not just "is there a nextval in here"
     *
     * `serial` expands to exactly one default: `nextval('…'::regclass)` and nothing else. A default
     * that CONTAINS a `nextval` call inside a larger expression — `COALESCE(nextval('s'), 1)`,
     * `nextval('s') + 0`, both constructible and both measured on 18.4 — is sequence-driven and can
     * even own its sequence, but it is not the macro. An identity column cannot express either one,
     * so recommending the conversion there would break the default; and calling it clean would claim
     * a check that never happened. The two shapes are therefore separated HERE, as a fact about the
     * text, and the rule decides what each one means.
     *
     * Deliberately blind to the sequence's NAME: `pg_get_expr` qualifies it or not depending on the
     * reading session's `search_path` (measured — the same sequence came back as `s` and as
     * `probe.s`), so a name parsed out of the default is not a name anything can be joined on. What
     * owns what is answered by `pg_depend`, which is where it is written down.
     */
    private static function sequenceDefaultShape(?string $default): ?string
    {
        if ($default === null || trim($default) === '') {
            return null;
        }

        $trimmed = trim($default);

        if (stripos($trimmed, 'nextval') === false) {
            return null;
        }

        return preg_match("/^nextval\\((?:'[^']*'|\"[^\"]*\")(?:::[a-z_. \"]+)?\\)$/i", $trimmed) === 1
            ? 'macro'
            : 'wrapped';
    }

    /**
     * The SQL keyword functions a server writes WITHOUT parentheses.
     *
     * They are spelled out rather than matched by a general "bare word" pattern, because such a
     * pattern would also swallow `true`, `false`, `null` and a bare enum literal — none of which is
     * a function, and each of which would then be reported as one.
     *
     * @var list<string>
     */
    private const array KEYWORD_FUNCTIONS = [
        'current_timestamp',
        'current_date',
        'current_time',
        'current_user',
        'session_user',
        'current_role',
        'localtime',
        'localtimestamp',
    ];

    /**
     * The name of the function a column defaults to, lower-cased, or null when it defaults to a
     * value rather than a call.
     *
     * ## Both spellings answer the same, and that took a fix
     *
     * A pattern that required parentheses saw `now()` and missed `CURRENT_TIMESTAMP`, so one column
     * declared two ways projected two different things — one carrying the function name and one
     * carrying nothing at all. Any rule reading this projection was therefore correct on a codebase
     * that wrote `now()` and silently blind on the one next to it that wrote the keyword.
     *
     * The precision argument is dropped HERE and only here: `CURRENT_TIMESTAMP(3)` is a different
     * DEFAULT from `CURRENT_TIMESTAMP` — the canonical form keeps them apart, and must — but it is
     * not a different FUNCTION, and this projection answers the second question.
     *
     * ## Only a zero-argument call, and the narrowness is the design
     *
     * `gen_random_uuid()`, `uuidv7()`, `now()` — those travel. A literal, an expression, a cast, a
     * call WITH arguments: all deliberately absent. The projection encodes each entry as
     * `name(value)` and a reader parses it by splitting on parentheses, so a default carrying its
     * own parentheses or commas cannot travel in one; truncating it to fit would put a value in a
     * rule's hands that is not what the server holds, which is worse than the rule having nothing.
     *
     * A rule reading `column_default_functions` therefore learns "this column defaults to calling X"
     * or nothing at all — never "this column has no default", which is a different fact and is not
     * this method's to state.
     */
    private static function defaultFunction(?string $default): ?string
    {
        if ($default === null || trim($default) === '') {
            return null;
        }

        $trimmed = trim($default);

        if (preg_match('/^([a-z_][a-z0-9_]*)\(\)$/i', $trimmed, $matches) === 1) {
            return mb_strtolower($matches[1]);
        }

        if (preg_match('/^([a-z_][a-z0-9_]*)(?:\(\s*\d+\s*\))?$/i', $trimmed, $matches) !== 1) {
            return null;
        }

        $name = mb_strtolower($matches[1]);

        return in_array($name, self::KEYWORD_FUNCTIONS, true) ? $name : null;
    }

    /**
     * The indexes that carry an INCLUDE payload beyond their key columns.
     *
     * ## Why this exists, and why an absence here is not "no payload"
     *
     * Measured on PostgreSQL 18.4: `CREATE INDEX ON t (a) INCLUDE (b)` and `CREATE INDEX ON t (a)`
     * report the SAME key columns, because `indnkeyatts` deliberately excludes the payload — an
     * INCLUDE column covers no lookup, so counting it as a key column would make a foreign key look
     * indexed when it is not.
     *
     * The consequence is that the two indexes are indistinguishable from their column lists alone.
     * A redundancy rule reading only those would report the one carrying the payload as redundant
     * to the one that does not, which is advice to drop the more useful of the two.
     *
     * MySQL has no covering-index syntax at all, so its reader states the flag as constantly false
     * rather than leaving it absent — an absent flag would read as "unknown" and force a rule to
     * answer undetermined on every MySQL table over a question this engine settles the same way
     * every time.
     *
     * @param  array<string, list<SchemaObject>>  $indexes
     * @return array<string, list<SchemaObject>>
     */
    private static function withPayload(array $indexes): array
    {
        $carrying = [];

        foreach ($indexes as $parent => $objects) {
            foreach ($objects as $index) {
                if ($index->getBool('has_include') === true) {
                    $carrying[$parent][] = $index;
                }
            }
        }

        return $carrying;
    }

    /**
     * One partial index's predicate in normalized form, or null when there is nothing to group on.
     *
     * Null covers two different states on purpose, because the caller treats them the same: the
     * index carries no predicate at all, or it carries one whose shape {@see IndexPredicate} refuses
     * to read. Both mean "this index cannot be grouped by condition", and neither is a defect.
     */
    private static function partialPredicate(SchemaObject $index): ?string
    {
        $predicate = $index->getString('predicate');

        if ($predicate === null || $predicate === '') {
            return null;
        }

        return IndexPredicate::parse($predicate)?->normalized;
    }

    /**
     * The access method and operator class this index groups under, or null when it does not group.
     *
     * ## Why a GIN index gets a universe and not a verdict
     *
     * `comparable_indexes` holds what may be compared against a b-tree's column list, and a GIN
     * index is correctly absent from it: it answers a different question, and the prefix arithmetic
     * that serves b-tree does not describe it. Measured on PostgreSQL 18.4 — a GIN index on
     * `(tags, doc)` serves a query touching `doc` ALONE, with nothing said about `tags`, because
     * multicolumn GIN matches any SUBSET of its columns rather than a leading run.
     *
     * That measurement is the reason this returns a group rather than admitting the index to the
     * existing one. Inside the group the method cancels, exactly as a shared predicate does — but
     * the arithmetic that survives is weaker, and the caller is the one that knows it: prefix is
     * sound for GIN and wrong for an access method nobody here has measured, so only EQUALITY
     * concludes anything. An extension can add an access method with any semantics it likes, and
     * "two indexes of the same method, class and columns are the same index" holds for all of them.
     *
     * ## The operator class is part of the KEY, not a refusal
     *
     * `text_pattern_ops` serves `LIKE 'foo%'` and the default class does not, so two indexes on one
     * column with different classes are two different indexes — which is why the class cannot be
     * ignored. Inside one class it cancels like the method does. Measured on the same server: a GIN
     * index over an array reports NO non-default class, because `array_ops` is gin's default, so the
     * class stays orthogonal to the method rather than duplicating it.
     *
     * Null for everything a b-tree comparison already covers, and for every index whose reading was
     * not complete enough to compare at all — see
     * {@see IndexComprehension::comparableApartFromItsMethod()}, which is the same set of questions
     * `of()` asks before it ever reaches the method.
     */
    private static function accessMethodKey(SchemaObject $index): ?string
    {
        $method = $index->getString('method');

        if (IndexComprehension::comparesByPrefix($method)) {
            return null;
        }

        if (! IndexComprehension::comparableApartFromItsMethod($index)) {
            return null;
        }

        // The class joins the key rather than the method alone, so `doc jsonb_path_ops` and a
        // default-class GIN on `doc` never land in one universe.
        return $method.'|'.($index->getString('operator_classes') ?? '');
    }

    /**
     * The partial indexes that share a condition with another partial index on the same table.
     *
     * ## The one inference that holds without implication
     *
     * Two partial indexes whose normalized predicates are IDENTICAL cover exactly the same rows. The
     * predicate therefore cancels, and the columns decide — the same arithmetic as for two ordinary
     * indexes, not a heuristic about which condition is narrower.
     *
     * Everything else stays out, and the exclusions are the point rather than a limitation:
     *
     * - **Different predicates** is an IMPLICATION question — does `WHERE a IS NULL` cover
     *   `WHERE a IS NULL AND b = 1`? — and implication is not built. Two such indexes never land in
     *   one group, so no rule can reach the pair.
     * - **A partial index against an UNCONDITIONAL one** is the tempting case and the dangerous one.
     *   It reads as "the full index covers the partial one", and as a statement about rows that is
     *   true; as advice it is not, because the partial index can be orders of magnitude smaller and
     *   dropping it is a loss rather than a tidy-up. That is a judgment somebody has to make, so an
     *   unconditional index is never in a group at all.
     * - **A group of one** is dropped. An index alone under its condition has nothing to be compared
     *   against, and carrying it would put a name into the projection that no comparison can use.
     *
     * ## Why a group TOKEN rather than the predicate itself
     *
     * The projection is a flat `name(...)` string, and a predicate contains commas, parentheses and
     * quotes — it would not survive the encoding, and a rule that string-compared the decoded halves
     * would be re-deciding equality that was already decided here. `g1`, `g2`, … are assigned by
     * sorting the distinct predicates, so the token is stable for a given schema and two readings of
     * it diff cleanly.
     *
     * @param  array<string, list<SchemaObject>>  $partial  table => its partial indexes with a readable predicate
     * @param  array<string, string>  $predicates  index qualified name => its normalized predicate
     * @return array{indexes: array<string, list<SchemaObject>>, groups: array<string, list<string>>}
     */
    private static function samePredicate(array $partial, array $predicates): array
    {
        return self::universesBy($partial, $predicates);
    }

    /**
     * One index bucket split into comparison universes by a shared attribute.
     *
     * ## What a universe is, and why two different attributes build one the same way
     *
     * An attribute that makes an index incomparable IN GENERAL still cancels between two indexes
     * that share it. A predicate does — two partial indexes under the same condition cover the same
     * rows, so the condition drops out and the columns decide. An access method does too: two GIN
     * indexes are not comparable against a b-tree, and they are perfectly comparable against each
     * other. The grouping is identical in both cases; what differs is the attribute and, crucially,
     * what the caller is then allowed to CONCLUDE inside a group — see the two readers in
     * {@see RedundantIndex}, which use different arithmetic.
     *
     * A group of one is dropped, and that is not tidiness: a token in the projection that no
     * comparison can use invites a reader to think something was compared.
     *
     * @param  array<string, list<SchemaObject>>  $bucket  table => the indexes eligible for grouping
     * @param  array<string, string>  $keys  index qualified name => the attribute it groups on
     * @return array{indexes: array<string, list<SchemaObject>>, groups: array<string, list<string>>}
     */
    private static function universesBy(array $bucket, array $keys): array
    {
        $indexes = [];
        $groups = [];

        foreach ($bucket as $parent => $objects) {
            $byKey = [];

            foreach ($objects as $index) {
                $byKey[$keys[$index->qualifiedName] ?? ''][] = $index;
            }

            // Sorted so the token a group gets depends on the schema and not on the order the
            // reader happened to walk it in.
            ksort($byKey, SORT_STRING);
            $token = 0;

            foreach ($byKey as $members) {
                if (count($members) < 2) {
                    continue;
                }

                $token++;

                foreach ($members as $index) {
                    $indexes[$parent][] = $index;
                    $groups[$parent][] = self::shortName($index).'(g'.$token.')';
                }
            }
        }

        return ['indexes' => $indexes, 'groups' => $groups];
    }

    /**
     * How each unique index treats NULLs — `name(distinct)` or `name(not_distinct)`.
     *
     * ## Why this is a THIRD value and not a flag
     *
     * Under the default, `NULLS DISTINCT`, a unique index does not constrain the rows a reader
     * thinks it does. Measured on PostgreSQL 18.4 and MySQL 8.4 alike: three rows sharing every
     * other column, each carrying a NULL in one member of the key, all coexist under `UNIQUE`. The
     * constraint holds for exactly the rows that do not need it.
     *
     * PostgreSQL 15 added `NULLS NOT DISTINCT`, which makes the key hold across those rows — so the
     * SAME shape is a defect or a correct schema depending on one catalog flag. MySQL has no such
     * mode at all.
     *
     * An index missing from this list therefore means the flag was NOT READ, and a rule must answer
     * undetermined rather than either verdict. Encoding only the hazardous ones would collapse
     * "nobody looked" into "this one is fine" — the exact failure a two-valued flag cannot avoid,
     * and the reason this projection spells the answer out instead of implying it by absence.
     *
     * @param  array<string, list<SchemaObject>>  $unique  table => its unique indexes, primary key excluded
     * @return array<string, list<string>>
     */
    private static function nullTreatment(array $unique): array
    {
        $treatment = [];

        foreach ($unique as $parent => $indexes) {
            foreach ($indexes as $index) {
                $flag = $index->getBool('nulls_not_distinct');

                if ($flag === null) {
                    continue;
                }

                $treatment[$parent][] = self::shortName($index).'('.($flag ? 'not_distinct' : 'distinct').')';
            }
        }

        return $treatment;
    }

    /**
     * One bucket of collected members, encoded against each table's own spelling map.
     *
     * @param  array<string, list<SchemaObject>>  $bucket  table => its members of one kind
     * @param  array<string, array<string, string|null>>  $spelling
     * @return array<string, list<string>>
     */
    private static function encodeMembers(array $bucket, array $spelling): array
    {
        $encoded = [];

        foreach ($bucket as $parent => $objects) {
            foreach ($objects as $object) {
                $encoded[$parent][] = self::entry($object, $spelling[$parent] ?? []);
            }
        }

        return $encoded;
    }

    /**
     * One member as `name(col, col)`, with every column spelled the way its column object spells it.
     *
     * @param  array<string, string|null>  $spelling  see {@see self::spell()}
     */
    private static function entry(SchemaObject $object, array $spelling): string
    {
        $columns = array_map(
            static fn (string $column): string => self::spell($column, $spelling),
            array_map(trim(...), explode(',', (string) $object->getString('key_columns'))),
        );

        return self::shortName($object).'('.implode(', ', $columns).')';
    }

    /**
     * A member's column token, rewritten into the spelling the table's column objects use.
     *
     * ## Why this exists, measured rather than assumed
     *
     * One column reaches a rule under THREE spellings, and they come from three different places in
     * the same reading. On PostgreSQL 18.4, for a column created as `"customerRef"`:
     *
     * | Where it comes from | What arrives |
     * |---|---|
     * | an index's `key_columns`, via `pg_get_indexdef(oid, n, true)` | `"customerRef"` — QUOTED |
     * | a constraint's `key_columns`, via `pg_attribute.attname` | `customerRef` — raw |
     * | a column object's short name, via the canonicalizer | `customerref` — folded |
     *
     * Every rule here joins one of those vocabularies to another by STRING: it takes a column out of
     * `primary_key` and looks it up in `column_types`, or checks a foreign key's columns against an
     * index's. On a table whose identifiers were quoted, that lookup misses every time — and the two
     * ways it misses are both bad. A rule that cannot find the type reports nothing, silently, about
     * the table it was written for. A rule that cannot match the index reports a foreign key as
     * unindexed while pointing at the index that covers it.
     *
     * No unit test could catch it, because a hand-built fixture spells the column the same way in
     * both places. It is only real where somebody quoted an identifier — which is every schema
     * migrated in from somewhere else.
     *
     * ## Why the rewrite is conservative in both directions
     *
     * A token that matches NO read column is returned untouched. It may be an expression from an
     * expression index — `pg_get_indexdef` yields the expression, deliberately, because a reader
     * told only "this is an expression" can say nothing useful about it — or a column the reading
     * never got. Rewriting something unrecognized would be the guessing the rest of this class
     * exists to avoid.
     *
     * A token whose key matches TWO read columns is also returned untouched, and that is the
     * important half. PostgreSQL can hold `foo` and `"Foo"` on one table; picking either would hand
     * a rule a confident answer about the wrong column. A rule seeing a name it cannot join is
     * strictly better than one seeing the wrong join, because the first shows up as an unanswered
     * question and the second as a wrong answer.
     *
     * @param  array<string, string|null>  $spelling  fold key => the column's spelling, or null when ambiguous
     */
    private static function spell(string $column, array $spelling): string
    {
        return $spelling[self::spellingKey($column)] ?? $column;
    }

    /**
     * The key two spellings of one column agree on: unquoted, case-folded.
     *
     * Both engines are covered by one key rather than by a per-driver rule, because the difference
     * is not between the engines — it is between two places in the SAME reading. MySQL's
     * `information_schema` reports column names unquoted everywhere, so the rewrite is a no-op
     * there; that is the shape of a normalization that is safe to apply unconditionally.
     */
    private static function spellingKey(string $column): string
    {
        return mb_strtolower(trim(trim($column), '"`'));
    }

    /**
     * The member's name without the qualification its table already carries.
     *
     * Two prefixes are tried because the engines qualify differently, measured: MySQL keys an index
     * by its TABLE (`db.orders.orders_idx`), PostgreSQL by its SCHEMA (`public.orders_idx`) — an
     * index is a schema-level object there. Stripping only the parent would leave every PostgreSQL
     * entry carrying a schema name, and stripping only the schema would leave every MySQL entry
     * carrying a table name. Neither is wrong, both are noise in a list somebody has to read.
     */
    private static function shortName(SchemaObject $object): string
    {
        $name = $object->qualifiedName;
        $parent = $object->parent ?? '';
        $schema = str_contains($parent, '.') ? substr($parent, 0, (int) strrpos($parent, '.')) : $parent;

        foreach ([$parent, $schema] as $prefix) {
            if ($prefix !== '' && str_starts_with($name, $prefix.'.')) {
                return substr($name, strlen($prefix) + 1);
            }
        }

        return $name;
    }

    /** Whether this constraint is a foreign key, in either engine's spelling. */
    private static function isForeignKey(SchemaObject $constraint): bool
    {
        // PostgreSQL stores a single letter, MySQL the SQL words. Both are read here rather than
        // normalized upstream, because the raw value is what each driver's other rules already use.
        if ($constraint->getString('contype') === 'f') {
            return true;
        }

        return $constraint->getString('constraint_type') === 'FOREIGN KEY';
    }

    /** @param  list<string>  $entries */
    private static function encode(array $entries): string
    {
        sort($entries);

        return implode('; ', $entries);
    }
}
