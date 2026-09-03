<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One grant: who may do what to which object, and whether they may pass it on.
 *
 * ## Why the privileges are a SET and never the catalog's own string
 *
 * PostgreSQL stores them as an ACL array (`app=arwdDxt/postgres`), MySQL as one `Y`/`N` column per
 * privilege. A rule that matched either spelling would be a rule about a format rather than about a
 * permission, and it would go quiet the day the format changed — which is exactly what the grammar
 * drift the canonicalization layer exists for. Here the answer to "may this account create objects"
 * is one method call, identical on both engines.
 *
 * ## PUBLIC is a grantee like any other, and that is deliberate
 *
 * PostgreSQL writes a grant to PUBLIC with an EMPTY grantee, which reads as "no grantee" to anything
 * that does not know the convention — and a grant to PUBLIC is the single most consequential row in
 * this whole reading, because it applies to every role that will ever exist. So it is normalized to
 * the literal name {@see self::PUBLIC_GRANTEE} at the reader, where the convention is known, rather
 * than left for each rule to remember.
 */
final readonly class GrantObject
{
    /** The name PUBLIC carries here — PostgreSQL's empty grantee, made explicit. */
    public const string PUBLIC_GRANTEE = 'PUBLIC';

    /**
     * @param  list<Privilege>  $privileges  sorted by value
     * @param  list<string>  $otherPrivileges  the engine's own names for privileges this vocabulary
     *                                         has no case for, sorted — never folded away
     * @param  list<string>  $structuralOtherPrivileges  which of those unmapped names change a SCHEMA
     *                                                   on this engine, upper-cased. Empty for an
     *                                                   engine whose privileges all map onto
     *                                                   canonical cases — see {@see self::isStructural()}
     */
    private function __construct(
        public string $grantee,
        public ?string $grantor,
        public SchemaObjectType $objectType,
        public string $objectName,
        public array $privileges,
        public array $otherPrivileges,
        public bool $grantable,
        public GrantOrigin $origin,
        public Readability $readability,
        public bool $coversEveryPrivilege,
        public array $structuralOtherPrivileges,
    ) {}

    /**
     * Build a canonical grant from the privileges KEYED BY THE ENGINE'S OWN NAME for each.
     *
     * The key is what makes the unmapped ones recoverable without a second list to keep in step: an
     * entry whose value is {@see Privilege::Other} still knows it was called `PROCESS`, so the reader
     * hands over one map instead of a list plus a parallel list of names that could drift apart.
     *
     * @param  array<string, Privilege>  $privileges  engine's own name => the case it maps to
     * @param  list<string>  $structuralOtherPrivileges  which of this engine's unmapped privilege
     *                                                   names change a SCHEMA — see
     *                                                   {@see self::isStructural()}. Empty for an
     *                                                   engine whose privileges all map onto
     *                                                   canonical cases.
     * @param  bool  $coversEveryPrivilege  whether this grant carries EVERY privilege its engine
     *                                      permits on this kind of object — `GRANT ALL PRIVILEGES`,
     *                                      whether or not it was written that way. Answered by the
     *                                      READER, because only a driver may hold an engine's
     *                                      vocabulary: PostgreSQL states its own set through
     *                                      `acldefault()`, MySQL through the grant-table columns. A
     *                                      rule computing it would need both, and the core is kept
     *                                      free of either on purpose.
     */
    public static function of(
        string $grantee,
        SchemaObjectType $objectType,
        string $objectName,
        array $privileges,
        Readability $readability,
        ?string $grantor = null,
        bool $grantable = false,
        GrantOrigin $origin = GrantOrigin::Project,
        bool $coversEveryPrivilege = false,
        array $structuralOtherPrivileges = [],
    ): self {
        $values = array_values(array_unique(array_map(static fn (Privilege $p): string => $p->value, $privileges)));
        sort($values);

        $others = array_values(array_unique(array_map(
            strtoupper(...),
            array_keys(array_filter($privileges, static fn (Privilege $p): bool => $p === Privilege::Other)),
        )));
        sort($others);

        return new self(
            trim($grantee) === '' ? self::PUBLIC_GRANTEE : trim($grantee),
            $grantor === null || trim($grantor) === '' ? null : trim($grantor),
            $objectType,
            trim($objectName),
            array_map(Privilege::from(...), $values),
            $others,
            $grantable,
            $origin,
            $readability,
            $coversEveryPrivilege,
            self::upperCased($structuralOtherPrivileges),
        );
    }

    /**
     * Upper-cased and de-duplicated, written as a loop rather than `array_map(strtoupper(...))`.
     *
     * The first-class callable form is what Rector asks for and what the static analyzer refuses —
     * it types `strtoupper` as `callable(mixed): mixed` against a `list<string>`. Two tools, one
     * expression, no spelling that satisfies both; a loop satisfies both and needs no suppression,
     * which is the rule here.
     *
     * @param  list<string>  $names
     * @return list<string>
     */
    private static function upperCased(array $names): array
    {
        $upper = [];

        foreach ($names as $name) {
            $one = strtoupper($name);

            if (! in_array($one, $upper, true)) {
                $upper[] = $one;
            }
        }

        return $upper;
    }

    public function has(Privilege $privilege): bool
    {
        return in_array($privilege, $this->privileges, true);
    }

    /**
     * Whether a rule should judge this grant — a grant to PUBLIC that PostgreSQL itself made is not a
     * finding, and a suite that opened with a hundred of them would be switched off in its first week.
     */
    public function isJudgeable(): bool
    {
        return $this->origin->isProjectDecision();
    }

    /** Whether this grant reaches every role on the server, present and future. */
    public function isToPublic(): bool
    {
        return $this->grantee === self::PUBLIC_GRANTEE;
    }

    /**
     * Whether it hands out the power to change the schema rather than the data in it.
     *
     * Asked here so the definition cannot drift between the rules that use it — but in TWO halves,
     * because one of them is not the same question on both engines.
     *
     * **The canonical half** is stated here and holds everywhere. `CREATE` makes an account able to
     * add objects; `TRUNCATE` destroys data with no `DELETE` trail; `ALTER SYSTEM` rewrites the
     * server's own configuration; and `TRIGGER` is what `CREATE TRIGGER` requires — a trigger is
     * exactly the thing an injection leaves behind, which the rules reading this already say in so
     * many words while this method did not ask about it.
     *
     * **The engine half** comes from the reader, and its absence was a real defect. Nearly every
     * MySQL privilege that changes a schema has no PostgreSQL equivalent, so `ALTER`, `DROP`,
     * `INDEX`, `CREATE ROUTINE` and `EVENT` all arrive as {@see Privilege::Other} carrying their own
     * name — and `TRUNCATE` and `ALTER SYSTEM` do not exist on MySQL at all. The canonical half
     * alone therefore asked, on MySQL, only whether the account held `CREATE`: an account that may
     * rebuild every table, drop every table and install a stored routine read as holding nothing
     * structural, and the rules asking came back silent.
     *
     * The list is supplied rather than kept here because only a driver may hold an engine's
     * vocabulary — an architecture test says so, and it is right. An engine whose privileges all map
     * onto canonical cases supplies nothing, which is the correct answer for PostgreSQL rather than
     * an omission.
     */
    public function isStructural(): bool
    {
        if ($this->has(Privilege::Create)) {
            return true;
        }
        if ($this->has(Privilege::Truncate)) {
            return true;
        }
        if ($this->has(Privilege::AlterSystem)) {
            return true;
        }
        if ($this->has(Privilege::Trigger)) {
            return true;
        }

        return array_any(
            $this->otherPrivileges,
            fn (string $name): bool => in_array($name, $this->structuralOtherPrivileges, true),
        );
    }

    /** Deterministic ordering: object, then grantee — the order a reader scans a report in. */
    public function sortKey(): string
    {
        return $this->objectType->value."\0".$this->objectName."\0".$this->grantee;
    }

    /**
     * @return array{grantee: string, grantor: string|null, object_type: string, object_name: string, privileges: list<string>, other_privileges: list<string>, grantable: bool, covers_every_privilege: bool, origin: string, readability: array{state: string, reason: string|null, withheld_fields: list<string>, detail: string|null}}
     */
    public function toArray(): array
    {
        return [
            'grantee' => $this->grantee,
            'grantor' => $this->grantor,
            'object_type' => $this->objectType->value,
            'object_name' => $this->objectName,
            'privileges' => array_map(static fn (Privilege $p): string => $p->value, $this->privileges),
            'other_privileges' => $this->otherPrivileges,
            'grantable' => $this->grantable,
            'covers_every_privilege' => $this->coversEveryPrivilege,
            'origin' => $this->origin->value,
            'readability' => $this->readability->toArray(),
        ];
    }
}
