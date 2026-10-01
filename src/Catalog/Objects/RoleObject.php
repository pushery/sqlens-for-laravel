<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Canonical\QuotedIdentifier;

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
     * The attributes that make an account dangerous to run an application as, on either engine.
     *
     * @see self::isPrivileged()
     */
    public const array PRIVILEGED = [
        RoleAttribute::Superuser,
        RoleAttribute::CreateRole,
        RoleAttribute::CreateDatabase,
        RoleAttribute::BypassRls,
        RoleAttribute::Replication,
    ];

    /**
     * @param  list<RoleAttribute>  $attributes  sorted by value
     * @param  list<string>  $memberships  role names this account is a member of, sorted
     * @param  list<string>  $reachableRoles  the roles reachable along chains that carry rights, sorted
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
         *
         * Over the chains that carry rights, because the questions asked of this set are about
         * rights: whether the account is exempt from row-level security as a table's owner, and
         * whether a grant is one it holds. Those are SET grants followed by INHERIT grants. A grant
         * with neither ends the chain even though it is a membership, and {@see self::$memberships}
         * still lists it. The three fields below are narrower.
         */
        public array $reachableRoles,
        /**
         * The attributes those reachable roles hold — what this account can BECOME, not what it is.
         *
         * Only roles at the end of a chain of grants that each carry SET TRUE count, because that is
         * the chain `SET ROLE` follows. A grant WITH SET FALSE is the hardening PostgreSQL 16 added
         * for exactly this, and a member behind one cannot take on the attributes of the role.
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
         * How each role the account can `SET ROLE` to is reached — `app -> deploy -> admin`, keyed by
         * the role at the end.
         *
         * A finding that says "this account reaches superuser" and stops is not resolvable: the person
         * fixing it has to know WHICH grant to revoke, and on a three-step chain that is two grants
         * they cannot see from the endpoint alone. The shortest path per role, because a diamond offers
         * several and the shortest is the one somebody acts on first.
         *
         * @var array<string, string>
         */
        public array $reachablePaths,
        /**
         * What each reachable role holds itself, keyed like {@see self::$reachablePaths}.
         *
         * `$reachableAttributes` is the union over all of them, which answers WHETHER the account can
         * become something and not THROUGH WHICH role. A finding that printed the first path it had
         * named a membership that grants nothing whenever a harmless role sorted before the one with
         * the attribute, and the advice beside it was to revoke exactly that membership.
         *
         * @var array<string, list<RoleAttribute>>
         */
        public array $reachableRoleAttributes,
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
     * @param  array<string, list<RoleAttribute>>  $reachableRoleAttributes
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
        array $reachableRoleAttributes = [],
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

        $held = [];

        foreach ($reachableRoleAttributes as $role => $roleAttributes) {
            $values = array_values(array_unique(array_map(
                static fn (RoleAttribute $attribute): string => $attribute->value,
                $roleAttributes,
            )));
            sort($values);
            $held[$role] = array_map(RoleAttribute::from(...), $values);
        }

        ksort($held, SORT_STRING);

        return new self(
            self::canonicalName($name),
            $host === null ? null : self::canonicalHost($host),
            array_map(RoleAttribute::from(...), $sortedAttributes),
            $sortedMemberships,
            $sortedReachable,
            array_map(RoleAttribute::from(...), $reachableValues),
            $reachablePaths,
            $held,
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
     * The MySQL form is the string-literal spelling of an account, with a quote inside a part
     * doubled, so a name holding one cannot end the literal early. It is the name for reading;
     * a statement uses {@see self::statementName()}.
     */
    public function identity(): string
    {
        return $this->host === null
            ? $this->name
            : sprintf("'%s'@'%s'", str_replace("'", "''", $this->name), str_replace("'", "''", $this->host));
    }

    /**
     * The account as a statement names it: `"app"` on PostgreSQL, `` `app`@`%` `` on MySQL.
     *
     * Every part is quoted as an identifier. MySQL 8.4 prints accounts this way itself in `SHOW
     * GRANTS`, measured, and a backtick-quoted part is read the same under every `sql_mode`, where a
     * string literal reads a backslash differently depending on `NO_BACKSLASH_ESCAPES`.
     */
    public function statementName(): string
    {
        return $this->host === null
            ? QuotedIdentifier::of('"', $this->name)
            : QuotedIdentifier::of('`', $this->name).'@'.QuotedIdentifier::of('`', $this->host);
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
     * MySQL only: `'app'@'%'` accepts every source address, and so does a pattern made of nothing but
     * wildcards and dots, such as `%.%.%.%`. A PostgreSQL role carries no host at all — where a
     * connection may come from is decided by `pg_hba.conf` there, which is a different object
     * entirely, so this answers false rather than pretending the question applies.
     */
    public function acceptsAnyHost(): bool
    {
        return $this->host !== null && str_contains($this->host, '%') && trim($this->host, '%_.') === '';
    }

    /**
     * Whether the host is a pattern over host NAMES, such as `%.example.com`.
     *
     * MySQL matches it against the name the client's address resolves to, so the account accepts
     * every host whose name fits. Two narrower shapes are deliberately not one:
     *
     * - An address pattern, such as `10.0.0.%` or `fe80::%`. MySQL matches an IP wildcard value only
     *   against IP addresses, never against a host name, so the pattern is an address range: the
     *   narrowing an open host is told to make, not a widening.
     * - `_` without `%`. It matches exactly one character, so `db_host.internal` accepts only the
     *   names that differ from it in that place.
     */
    public function hasHostNamePattern(): bool
    {
        if ($this->host === null || ! str_contains($this->host, '%') || $this->acceptsAnyHost()) {
            return false;
        }

        // Digits, dots and wildcards are an IPv4 pattern, and only an IPv6 address carries a colon.
        return preg_match('/^[0-9.%_]+$/', $this->host) !== 1 && ! str_contains($this->host, ':');
    }

    public function has(RoleAttribute $attribute): bool
    {
        return in_array($attribute, $this->attributes, true);
    }

    /**
     * How the account reaches the nearest role holding this attribute, or null when it does not.
     */
    public function pathTo(RoleAttribute $attribute): ?string
    {
        return $this->pathsTo($attribute)[0] ?? null;
    }

    /**
     * The path to every reachable role that holds this attribute itself, shortest first.
     *
     * Every one of them, because each is a membership somebody has to revoke: with two roles
     * carrying the attribute, a finding that named one would leave the other route open after the
     * fix. Ordered by length and then by text, so an unchanged server gives the same list on every
     * run and a diff between two reports only moves when the server did.
     *
     * @return list<string>
     */
    public function pathsTo(RoleAttribute $attribute): array
    {
        $paths = [];

        foreach ($this->reachablePaths as $role => $path) {
            if (in_array($attribute, $this->reachableRoleAttributes[$role] ?? [], true)) {
                $paths[] = $path;
            }
        }

        usort($paths, static fn (string $a, string $b): int => [substr_count($a, ' -> '), $a] <=> [substr_count($b, ' -> '), $b]);

        return $paths;
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
        return array_any(self::PRIVILEGED, fn (RoleAttribute $attribute): bool => $this->has($attribute));
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
     * @return array{name: string, host: string|null, attributes: list<string>, memberships: list<string>, reachable_roles: list<string>, reachable_paths: array<string, string>, reachable_role_attributes: array<string, list<string>>, reachable_attributes: list<string>, hash_type: string, valid_until: string|null, system: bool, connection_role: bool, usable: bool, readability: array{state: string, reason: string|null, withheld_fields: list<string>, detail: string|null}}
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
            'reachable_role_attributes' => array_map(
                static fn (array $held): array => array_map(static fn (RoleAttribute $attribute): string => $attribute->value, $held),
                $this->reachableRoleAttributes,
            ),
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
