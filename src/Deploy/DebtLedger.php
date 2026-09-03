<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Illuminate\Filesystem\Filesystem;

/**
 * The migration debt account: a versioned repository FILE, never a database table.
 *
 * ## Why a file at all
 *
 * A debt outlives the run that found it, so it has to be recorded somewhere — and the one place
 * this package will not write is the database it is watching. A table would need a migration, a
 * write privilege and a schema of its own on the very instance whose safety is the point. In Git it
 * reviews like code: the diff shows what a change to a migration actually cost, and the history
 * says who accepted it.
 *
 * ## Why the order is documented rather than incidental
 *
 * Two runs over the same state must produce a byte-identical file, or every run turns into a diff
 * and nobody reads them. The order is driver, then kind, then object, then migration, then id —
 * grouping everything about one engine, then one kind of debt, so a change touches one region of
 * the file rather than scattering. The id is the last tiebreaker and makes the order TOTAL: two
 * entries agreeing on all four leading keys still have a defined position, which is exactly what
 * "same state, same file" requires.
 *
 * Every comparison is a byte comparison. A locale-aware collation would sort the same entries
 * differently on two machines, and the file would churn for a reason no reader could see.
 *
 * ## Why absence is reported rather than swallowed
 *
 * A missing ledger is not an error for the WRITE path — the first run in a project has nothing to
 * load. It is not automatically fine for a READER either: "no debts recorded" and "nobody has ever
 * recorded debts here" are different statements, and only the consumer knows which one matters.
 * {@see wasPresent()} hands that distinction on instead of deciding it here.
 */
final readonly class DebtLedger
{
    /** The root field carrying the format version. */
    public const string SCHEMA_KEY = 'schema';

    /** The root field holding the recorded debts. */
    public const string ENTRIES_KEY = 'entries';

    /** Where the ledger lives when the project has not named a path. */
    public const string DEFAULT_PATH = 'sqlens-debt.json';

    /** @param  list<DebtEntry>  $entries  already in the documented order */
    private function __construct(
        public array $entries,
        private bool $present,
        public ?DebtLedgerRefusal $refusal = null,
    ) {}

    /**
     * A ledger from entries in ANY order.
     *
     * @param  list<DebtEntry>  $entries
     */
    public static function of(array $entries, bool $wasPresent = true): self
    {
        usort($entries, self::order(...));

        return new self($entries, $wasPresent);
    }

    /**
     * The ledger at a path — empty when there is no file, refused when there is one it cannot act on.
     *
     * Forgiving of ABSENCE and of nothing else. A file that exists but does not parse, or that
     * declares a format this build has never seen, is not an empty ledger: reading it as one would
     * report a project as owing nothing at the moment it might owe the most, and that answer is
     * both wrong and reassuring. Those come back carrying a {@see DebtLedgerRefusal} instead, which
     * the consulting check turns into a named `undetermined` — never a `pass`, and never a thrown
     * exception that would take a whole lint run down over a file most of it never reads.
     */
    public static function load(Filesystem $files, string $path): self
    {
        if (! $files->exists($path)) {
            return new self([], false);
        }

        $decoded = json_decode((string) $files->get($path), associative: true);

        if (! is_array($decoded) || array_is_list($decoded)) {
            return new self([], true, DebtLedgerRefusal::unreadable(
                $path,
                'it did not parse as a JSON object (got '.get_debug_type($decoded).')',
            ));
        }

        $schema = $decoded[self::SCHEMA_KEY] ?? null;

        // The version is checked BEFORE the entries, and the order is the point: entries written in
        // a shape this build does not understand would be dropped one by one and the run would end
        // with a plausible, smaller number. Refusing first is what stops that from being possible.
        if (! is_int($schema) || ! DebtLedgerSchema::supports($schema)) {
            return new self([], true, DebtLedgerRefusal::unsupportedSchema(
                $path,
                is_int($schema) ? 'schema '.$schema : 'no integer schema (got '.get_debug_type($schema).')',
            ));
        }

        $entries = $decoded[self::ENTRIES_KEY] ?? null;

        if (! is_array($entries) || ! array_is_list($entries)) {
            return new self([], true, DebtLedgerRefusal::unreadable(
                $path,
                'its `'.self::ENTRIES_KEY.'` field is not a list (got '.get_debug_type($entries).')',
            ));
        }

        $recorded = [];

        foreach ($entries as $raw) {
            if (! is_array($raw)) {
                continue;
            }

            $entry = self::entryFrom($raw);

            // An acknowledgment with no reason is not an acknowledgment — it is a suppression
            // wearing one's clothes, and this package refuses those everywhere else by the same
            // argument the config validator uses for an ignore list naming a rule that does not
            // exist. The state means "somebody looked at this and decided to carry it"; without the
            // decision written down, the next reader inherits a debt that has stopped escalating
            // and no way to find out why.
            //
            // Refused at LOAD, so no consumer ever sees a half-acknowledged entry and has to decide
            // for itself what one means.
            if ($entry->state === DebtState::Acknowledged && trim($entry->reason) === '') {
                return new self([], true, DebtLedgerRefusal::unreadable(
                    $path,
                    'the entry for `'.$entry->object.'` is `acknowledged` with no `reason`. An '
                    .'acknowledgment is a decision somebody made; without the reason written down '
                    .'it is a suppression nobody argued for, and the next reader has no way to find out '
                    .'why this debt stopped escalating',
                ));
            }

            $recorded[] = $entry;
        }

        return self::of($recorded);
    }

    /** Whether this ledger could be acted on at all. */
    public function isUsable(): bool
    {
        return ! $this->refusal instanceof DebtLedgerRefusal;
    }

    /** Whether a ledger file was there to read. */
    public function wasPresent(): bool
    {
        return $this->present;
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /**
     * This ledger plus those entries, with an entry replacing the recorded one of the same identity.
     *
     * Replacing rather than appending is what keeps the account an ACCOUNT: a debt seen again is the
     * same debt, and a ledger that grew a row per run would report a number that only says how often
     * the tool ran.
     */
    public function merge(DebtEntry ...$entries): self
    {
        $byId = [];

        foreach ([...$this->entries, ...$entries] as $entry) {
            $byId[$entry->id] = $entry;
        }

        return self::of(array_values($byId), $this->present);
    }

    /**
     * The file's exact bytes, trailing newline included.
     *
     * The newline is not cosmetic: a file without one makes every tool that appends to it produce a
     * broken first line, and Git reports the last entry as changed whenever a new one is added.
     */
    public function toJson(): string
    {
        $root = [
            self::SCHEMA_KEY => DebtLedgerSchema::CURRENT,
            self::ENTRIES_KEY => array_map(static fn (DebtEntry $entry): array => $entry->toArray(), $this->entries),
        ];

        return json_encode($root, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    }

    /** Write the ledger, creating the directory it lives in when it is not there yet. */
    public function write(Filesystem $files, string $path): void
    {
        $directory = dirname($path);

        if (! $files->isDirectory($directory)) {
            $files->makeDirectory($directory, recursive: true);
        }

        $files->put($path, $this->toJson());
    }

    /**
     * One recorded entry, read back.
     *
     * Built through the same factory a fresh entry uses, so the identity is DERIVED rather than
     * trusted: a hand-edited id that no longer matches its own kind and object would otherwise
     * survive a round trip and split one debt into two.
     *
     * @param  array<array-key, mixed>  $raw
     */
    private static function entryFrom(array $raw): DebtEntry
    {
        return DebtEntry::of(
            kind: self::text($raw, 'kind'),
            ruleId: self::text($raw, 'rule_id'),
            driver: self::text($raw, 'driver'),
            object: self::text($raw, 'object'),
            migration: self::text($raw, 'migration'),
            firstSeen: self::text($raw, 'first_seen'),
            state: DebtState::tryFrom(self::text($raw, 'state')) ?? DebtState::Open,
            reason: self::text($raw, 'reason'),
            reviewAt: ($review = self::text($raw, 'review_at')) === '' ? null : $review,
            // Null for a schema-1 entry, which has no such key — and null is what asks the factory
            // to infer it from the migration reference. That inference is how a version-1 ledger
            // reads as version 2 with nothing lost and no rewriting step.
            origin: DebtOrigin::tryFrom(self::text($raw, 'origin')),
        );
    }

    /** @param  array<array-key, mixed>  $raw */
    private static function text(array $raw, string $key): string
    {
        $value = $raw[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * The documented total order, byte by byte.
     */
    private static function order(DebtEntry $a, DebtEntry $b): int
    {
        return strcmp($a->driver, $b->driver)
            ?: strcmp($a->kind, $b->kind)
            ?: strcmp($a->object, $b->object)
            ?: strcmp($a->migration, $b->migration)
            ?: strcmp($a->id, $b->id);
    }
}
