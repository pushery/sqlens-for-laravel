<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * One database account, in the form a driver-neutral rule can judge.
 *
 * ## Why both engines are mapped onto this and not read raw
 *
 * A rule that regexed `pg_roles` would be a second rule on MySQL, and the second one is always the
 * one nobody writes — so the two engines' shapes are reconciled once, at the edge, and every rule
 * downstream sees one vocabulary. The reconciliation is not cosmetic:
 *
 * - **Identity.** A PostgreSQL role is a name; a MySQL account is a name AND a host, and
 *   `'app'@'10.0.0.%'` and `'app'@'%'` are two different accounts with different powers. So the host
 *   is a field rather than being folded into the name, and it is null on PostgreSQL — a real
 *   difference, not a missing value.
 * - **Attributes.** PostgreSQL states them as boolean columns, MySQL as global privileges. Both
 *   arrive as a {@see RoleAttribute} set, which is what lets one rule ask "may this account create
 *   roles" on either engine.
 * - **Memberships.** Both engines have role membership; only the spelling differs. Sorted, so two
 *   readings of the same server compare equal and a fixture diff means something changed.
 *
 * ## The readability field is not optional, and this is the object that proves why
 *
 * `pg_roles` hands out every role while masking each one's password (measured: `rolpassword` is
 * `********` for every role, superuser included). So the SET is complete and every member of it is
 * `partial` — two facts that a set-level completeness flag cannot express at the same time. A rule
 * about hash types reading such an object must see `withheld`, not `none`.
 */
final readonly class RoleObject
{
    /**
     * @param  list<RoleAttribute>  $attributes  sorted by value
     * @param  list<string>  $memberships  role names this account is a member of, sorted
     * @param  list<string>  $reachableRoles  the transitive closure of that, sorted
     * @param  list<RoleAttribute>  $reachableAttributes  what those roles hold, sorted
     */
    private function __construct(
        public string $name,
        public ?string $host,
        public array $attributes,
        public array $memberships,
        /**
         * Every role reachable through the membership graph, direct ones included — sorted.
         *
         * The transitive closure rather than one hop, because that is what the exposure is: `app` is a
         * member of `deploy`, `deploy` is a member of `admin`, and `app` can become `admin` in two
         * steps that no single-hop reading shows.
         */
        public array $reachableRoles,
        /**
         * The attributes those reachable roles hold — what this account can BECOME, not what it is.
         *
         * The distinction is the engine's, not ours, and getting it wrong would make the reader claim
         * something PostgreSQL does not do: role ATTRIBUTES are not inherited through membership. A
         * member of a superuser role is not a superuser — it can `SET ROLE` and then be one. The
         * exposure is real and mostly equivalent in practice, but a rule that reported the account AS
         * a superuser would be making a false statement about the catalog, and the first person to
         * check `pg_roles` by hand would stop believing the tool.
         */
        public array $reachableAttributes,
        /**
         * How each reachable role is reached — `app -> deploy -> admin`, keyed by the role at the end.
         *
         * A finding that says "this account reaches superuser" and stops is not resolvable: the person
         * fixing it has to know WHICH grant to revoke, and on a three-step chain that is two grants
         * they cannot see from the endpoint alone. The shortest path per role, because a diamond offers
         * several and the shortest is the one somebody acts on first.
         *
         * @var array<string, string>
         */
        public array $reachablePaths,
        public PasswordHashType $hashType,
        public ?string $validUntil,
        /**
         * Whether the ENGINE owns this account rather than the project.
         *
         * Without it every rule in this suite reports false positives on a FRESH server: MySQL ships
         * `mysql.sys`, `mysql.session` and `mysql.infoschema`, PostgreSQL ships the `pg_` predefined
         * roles, and none of them is anybody's decision. Marked once at the reader — each engine knows
         * its own — instead of a hard-coded name list repeated in every rule that would then drift.
         */
        public bool $system,
        /**
         * Whether this is the account the audit itself connected as.
         *
         * The rules about dangerous attributes judge THIS account and no other, and the distinction is
         * what keeps them usable: every PostgreSQL server has a `postgres` superuser and every MySQL
         * server a `root`, so a rule reporting every privileged account would report one on a database
         * created thirty seconds ago. What a project can act on is the role its application connects
         * as — which is also the only one the finding can name a fix for.
         */
        public bool $connectionRole,
        /** Whether the account is locked or its password expired — it exists and cannot be used as is. */
        public bool $usable,
        /**
         * How many ordinary tables this role OWNS in the application's schemas, or null when the
         * reading did not establish it.
         *
         * Ownership is a DDL right for which no grant exists: an owner may `ALTER` and `DROP` its
         * tables outright, and the privilege appears in `pg_class.relowner` and in no grant row at
         * all. A check that reads only grants sees nothing here and reports silence — which is the
         * one thing this package refuses to let a check do.
         *
         * Null is `undetermined`, never zero: a reading that could not ask must not answer "owns
         * nothing", which is the shape a clean server has.
         */
        public ?int $ownedTables,
        public Readability $readability,
    ) {}

    /**
     * Build a canonical role.
     *
     * @param  list<RoleAttribute>  $attributes
     * @param  list<string>  $memberships
     * @param  list<string>  $reachableRoles
     * @param  list<RoleAttribute>  $reachableAttributes
     * @param  array<string, string>  $reachablePaths
     */
    public static function of(
        string $name,
        array $attributes,
        Readability $readability,
        ?string $host = null,
        array $memberships = [],
        PasswordHashType $hashType = PasswordHashType::Withheld,
        ?string $validUntil = null,
        array $reachableRoles = [],
        array $reachableAttributes = [],
        array $reachablePaths = [],
        bool $system = false,
        bool $connectionRole = false,
        bool $usable = true,
        ?int $ownedTables = null,
    ): self {
        // Sorted and deduplicated on both list fields. Determinism is the point: the same server read
        // twice must produce byte-identical output, and an attribute set that followed catalog row
        // order would reshuffle whenever the server did.
        $sortedAttributes = array_values(array_unique(array_map(
            static fn (RoleAttribute $attribute): string => $attribute->value,
            $attributes,
        )));
        sort($sortedAttributes);

        $sortedMemberships = array_values(array_unique(array_map(self::canonicalName(...), $memberships)));
        sort($sortedMemberships);

        $sortedReachable = array_values(array_unique(array_map(self::canonicalName(...), $reachableRoles)));
        sort($sortedReachable);

        $reachableValues = array_values(array_unique(array_map(
            static fn (RoleAttribute $attribute): string => $attribute->value,
            $reachableAttributes,
        )));
        sort($reachableValues);

        return new self(
            self::canonicalName($name),
            $host === null ? null : self::canonicalHost($host),
            array_map(RoleAttribute::from(...), $sortedAttributes),
            $sortedMemberships,
            $sortedReachable,
            array_map(RoleAttribute::from(...), $reachableValues),
            $reachablePaths,
            $hashType,
            $validUntil === null || trim($validUntil) === '' ? null : trim($validUntil),
            $system,
            $connectionRole,
            $usable,
            $ownedTables,
            $readability,
        );
    }

    /**
     * The identity a report prints and a fixture compares: `name` on PostgreSQL, `'name'@'host'` on
     * MySQL.
     *
     * The MySQL form is quoted the way MySQL itself writes it in `SHOW GRANTS`, so an operator can
     * paste the identity straight into a `REVOKE` without translating it.
     */
    public function identity(): string
    {
        return $this->host === null ? $this->name : sprintf("'%s'@'%s'", $this->name, $this->host);
    }

    /**
     * Whether this is an ANONYMOUS account — one whose user name is empty.
     *
     * A typed question rather than a `=== ''` in each rule, because the empty string is exactly the
     * value a reader is tempted to treat as "absent" and skip past. It is not absent here: MySQL
     * accepts `''@'host'` as a real account, and anyone connecting from a matching host under ANY
     * name it does not otherwise know is authenticated as it. The reader keeps those rows on purpose.
     *
     * PostgreSQL answers false by construction: `pg_authid.rolname` is the catalog key and cannot be
     * empty, so there is no such thing to find.
     */
    public function isAnonymous(): bool
    {
        return $this->name === '';
    }

    /**
     * Whether the account's host pattern lets it connect from anywhere.
     *
     * MySQL only: `'app'@'%'` accepts every source address, and `_` is its single-character wildcard.
     * A PostgreSQL role carries no host at all — where a connection may come from is decided by
     * `pg_hba.conf` there, which is a different object entirely, so this answers false rather than
     * pretending the question applies.
     */
    public function hasWildcardHost(): bool
    {
        return $this->host !== null && (str_contains($this->host, '%') || str_contains($this->host, '_'));
    }

    public function has(RoleAttribute $attribute): bool
    {
        return in_array($attribute, $this->attributes, true);
    }

    /**
     * How the account reaches the first role holding this attribute, or null when it does not.
     *
     * The first by NAME rather than the first found: two roles may both carry the attribute, and a
     * finding whose path changed between two runs of an unchanged server would make every diff noise.
     */
    public function pathTo(RoleAttribute $attribute): ?string
    {
        foreach ($this->reachableRoles as $role) {
            if (isset($this->reachablePaths[$role]) && in_array($attribute, $this->reachableAttributes, true)) {
                return $this->reachablePaths[$role];
            }
        }

        return null;
    }

    /**
     * Whether the account can GET this attribute by switching to a role it is a member of.
     *
     * Deliberately separate from {@see self::has()}: the account does not hold it, and a rule that
     * conflated the two would report a plain application role as a superuser. What it may say is that
     * one `SET ROLE` away, it is one — which is a finding of its own, with its own wording.
     */
    public function canReach(RoleAttribute $attribute): bool
    {
        return in_array($attribute, $this->reachableAttributes, true);
    }

    /**
     * Whether the account holds any of the attributes that make it dangerous to run an application
     * as — asked here so the two engines' notions of "too much power" cannot drift apart between
     * rules.
     */
    public function isPrivileged(): bool
    {
        return array_any([RoleAttribute::Superuser, RoleAttribute::CreateRole, RoleAttribute::CreateDatabase, RoleAttribute::BypassRls, RoleAttribute::Replication], fn (RoleAttribute $attribute): bool => $this->has($attribute));
    }

    /** The deterministic sort key: identity, so two readings of a server order identically. */
    public function sortKey(): string
    {
        return $this->name."\0".($this->host ?? '');
    }

    public function equals(self $other): bool
    {
        return $this->toArray() === $other->toArray();
    }

    /**
     * @return array{name: string, host: string|null, attributes: list<string>, memberships: list<string>, reachable_roles: list<string>, reachable_paths: array<string, string>, reachable_attributes: list<string>, hash_type: string, valid_until: string|null, system: bool, connection_role: bool, usable: bool, readability: array{state: string, reason: string|null, withheld_fields: list<string>, detail: string|null}}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'host' => $this->host,
            'attributes' => array_map(static fn (RoleAttribute $attribute): string => $attribute->value, $this->attributes),
            'memberships' => $this->memberships,
            'reachable_roles' => $this->reachableRoles,
            'reachable_paths' => $this->reachablePaths,
            'reachable_attributes' => array_map(static fn (RoleAttribute $attribute): string => $attribute->value, $this->reachableAttributes),
            'hash_type' => $this->hashType->value,
            'valid_until' => $this->validUntil,
            'system' => $this->system,
            'connection_role' => $this->connectionRole,
            'usable' => $this->usable,
            'readability' => $this->readability->toArray(),
        ];
    }

    /**
     * An identifier as the catalog means it, with the engine's quoting removed and nothing else
     * changed.
     *
     * Case is deliberately preserved. PostgreSQL folds an UNQUOTED identifier to lower case at parse
     * time, so what the catalog holds is already the truth; MySQL account names are case-sensitive.
     * Lower-casing here would merge `"App"` and `app` on PostgreSQL — two roles that genuinely
     * coexist — and would rename a MySQL account that does exist into one that does not.
     */
    private static function canonicalName(string $name): string
    {
        $trimmed = trim($name);

        if (strlen($trimmed) >= 2 && str_starts_with($trimmed, '"') && str_ends_with($trimmed, '"')) {
            return str_replace('""', '"', substr($trimmed, 1, -1));
        }

        if (strlen($trimmed) >= 2 && str_starts_with($trimmed, '`') && str_ends_with($trimmed, '`')) {
            return str_replace('``', '`', substr($trimmed, 1, -1));
        }

        if (strlen($trimmed) >= 2 && str_starts_with($trimmed, "'") && str_ends_with($trimmed, "'")) {
            return str_replace("''", "'", substr($trimmed, 1, -1));
        }

        return $trimmed;
    }

    /**
     * A MySQL host pattern, unquoted and lower-cased.
     *
     * Lower-cased where the name is not, because MySQL compares host patterns case-insensitively —
     * `'app'@'LOCALHOST'` and `'app'@'localhost'` are one account, and keeping both spellings would
     * make a set look like it holds two.
     */
    private static function canonicalHost(string $host): string
    {
        return strtolower(self::canonicalName($host));
    }
}
