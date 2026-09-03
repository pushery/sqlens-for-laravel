<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Canonical;

use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A stable hash of one catalog object's canonical form — the unit a drift comparison compares.
 *
 * ## Why an object hash beside the snapshot's
 *
 * {@see CatalogSnapshot::hash()} answers "did this reading change at all".
 * That is the wrong grain for a comparison: a run over four hundred tables would learn only that
 * something moved. This answers the same question per object, so a comparator can walk two readings
 * and stop at the entries whose hashes differ instead of diffing every field of every one.
 *
 * ## The volatile register lives HERE, and the snapshot borrows it
 *
 * Both the fingerprint and the snapshot's serialization have to ignore exactly the same attributes.
 * Two copies of that list would drift, and the failure would be quiet in the worst way: a hash that
 * ignored a counter while the serialization kept it would report two objects as identical and then
 * print a diff between them.
 *
 * So there is one register, with a reason per entry, and the snapshot reads it from here.
 *
 * ## What is deliberately NOT normalized here
 *
 * Nothing. By the time an object reaches this class its defaults and collations have already been
 * through {@see CatalogCanonicalizer} — the reader runs them as it reads. A second normalization at
 * this layer would be the parallel path `OneCanonicalizationPathTest` exists to forbid.
 */
final readonly class CatalogObjectFingerprint
{
    /**
     * The attributes a comparison must IGNORE, each with the reason it is noise.
     *
     * A register rather than a bare list: "it was already like that" is not a reason, and an entry
     * nobody can justify is one nobody dares remove either.
     *
     * Every one of these changes without the schema changing. Left in, they would make a drift
     * comparison report a difference on two readings of one untouched database — and a comparator
     * that reports changes nobody made is one whose output gets skimmed, which is the failure this
     * whole layer exists to prevent.
     *
     * @var array<string, string>
     */
    public const array VOLATILE_ATTRIBUTES = [
        // NOTHING READS THIS TODAY, and the line stays anyway — with that said out loud, because an
        // entry whose absence changes nothing is one a later reader deletes as dead.
        //
        // It is kept as a guard ahead of a reader that has not been written: the counter is real
        // noise the moment somebody selects it, and it would arrive under exactly this name. What
        // it must NOT do is what it did until 2026-08-18 — the MySQL column reader emitted a
        // boolean called `auto_increment` ("does this column auto-increment"), the register matched
        // it by name, and a column that gained or lost AUTO_INCREMENT was therefore invisible to
        // every comparison. That boolean is now `auto_increments`; the two concepts have two names.
        'auto_increment' => "MySQL's next value for the table. It moves on every insert, so two "
            .'readings minutes apart disagree about a schema nobody touched.',

        'actual_version' => 'the version an extension is CURRENTLY at on this server. It changes '
            .'when the server is upgraded, which is not a schema change the project made.',

        'recorded_version' => 'the version the catalog records for an extension, for the same '
            .'reason — an operator upgrading an extension is not schema drift.',

        // The three below belong to MySQL's scheduled events, the one object type that rewrites its
        // own catalog row BY RUNNING. Each reason is a measurement against MySQL 8.4.10 with the
        // scheduler live, not a reading of the manual.
        'last_executed' => 'the wall-clock of an event\'s most recent run. Measured moving on every '
            .'execution of a one-second event, so two readings four seconds apart disagree about a '
            .'schedule nobody altered.',

        'starts' => 'when an event\'s schedule begins. A schedule declared without an explicit '
            .'STARTS inherits the moment of CREATION — measured identical to CREATED to the second '
            .'— so the live database and a freshly built shadow disagree permanently, for no '
            .'reason but their ages.',

        // NOT called `status`, and the pair of names is the whole point — the same trap the
        // `auto_increment` entry above documents. A RECURRING event's status IS schema: somebody
        // ran ALTER EVENT ... DISABLE, and a comparison that could not see it would be worthless.
        // A ONE TIME event declared ON COMPLETION PRESERVE flips itself to DISABLED the moment it
        // fires (measured), which is a fact about execution wearing the same word. So the reader
        // emits `status` for the first and `execution_status` for the second, and only the second
        // one is noise.
        'execution_status' => 'whether a ONE TIME event has already fired. It changes by the event '
            .'running, which is the event working rather than the schema drifting.',
    ];

    /** Unit and record separators — bytes no identifier or type name contains, so fields cannot bleed together. */
    private const string UNIT = "\x1f";

    private const string RECORD = "\x1e";

    /**
     * The attributes of one object that a comparison may read, sorted.
     *
     * @return array<string, scalar|null>
     */
    public static function comparableAttributes(SchemaObject $object): array
    {
        return array_diff_key($object->attributes(), self::VOLATILE_ATTRIBUTES);
    }

    /**
     * The hash of one object.
     *
     * Identity travels with it — type and qualified name — because two columns of different tables
     * can carry byte-identical attributes, and a hash that collided there would let a comparison
     * pair the wrong ones.
     *
     * The value is rendered rather than cast: `false` and `null` and `0` are three different answers
     * about a column, and PHP's string cast turns two of them into the empty string.
     */
    public static function of(SchemaObject $object): string
    {
        $fields = [$object->type->value, $object->qualifiedName, $object->parent ?? ''];

        foreach (self::comparableAttributes($object) as $key => $value) {
            $fields[] = $key.self::UNIT.self::render($value);
        }

        return hash('sha256', implode(self::RECORD, $fields));
    }

    /** One attribute value, with its THREE-valued nature intact. */
    private static function render(bool|int|float|string|null $value): string
    {
        return match (true) {
            $value === null => 'null',
            $value === true => 'true',
            $value === false => 'false',
            default => (string) $value,
        };
    }
}
