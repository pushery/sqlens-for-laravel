<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

/**
 * The defaults `ALTER ROLE … SET` and `ALTER DATABASE … SET` stored for this database, and the role
 * this reading logged in as.
 *
 * `reset_val` in `pg_settings` answers for one role: the one reading it. A fresh session starts from
 * the server's configuration and takes, in rising precedence, the default for every role, the one
 * for this database, the role's own for every database, and the role's own for this database. So a
 * reading role with a default of its own sees that default rather than the server's value, and a role
 * that runs the migrations with one of its own starts somewhere this reading never sees. These rows
 * are what tells the two apart.
 *
 * The values keep the spelling they were stored with, `10s` rather than `10000`.
 */
final readonly class RoleDefaults
{
    /**
     * One entry per stored setting. `role` is null in a default for every role, and `thisDatabase` is
     * false in a default for every database.
     *
     * @param  string  $reader  the role this reading logged in as, whose defaults `reset_val` includes
     * @param  list<array{thisDatabase: bool, role: ?string, name: string, value: string}>  $entries
     * @param  bool  $read  false when the catalog could not be read, and the entries are then empty
     */
    private function __construct(
        public string $reader,
        private array $entries,
        public bool $read,
    ) {}

    /**
     * @param  list<array{thisDatabase: bool, role: ?string, name: string, value: string}>  $entries
     */
    public static function of(string $reader, array $entries): self
    {
        return new self($reader, $entries, true);
    }

    public static function unread(): self
    {
        return new self('', [], false);
    }

    /** The default a role carries of its own for the setting: the one for this database, else the one for every database. */
    public function own(string $role, string $name): ?string
    {
        return $this->stored(true, $role, $name) ?? $this->stored(false, $role, $name);
    }

    /** The default every role starts from: this database's, else the one set for every role. */
    public function shared(string $name): ?string
    {
        return $this->stored(true, null, $name) ?? $this->stored(false, null, $name);
    }

    /**
     * The roles that carry a default of their own for the setting, each once.
     *
     * @return list<string>
     */
    public function rolesWithOwn(string $name): array
    {
        $roles = [];

        foreach ($this->entries as $entry) {
            if ($entry['role'] !== null && $entry['name'] === $name && ! in_array($entry['role'], $roles, true)) {
                $roles[] = $entry['role'];
            }
        }

        return $roles;
    }

    private function stored(bool $thisDatabase, ?string $role, string $name): ?string
    {
        foreach ($this->entries as $entry) {
            if ($entry['thisDatabase'] === $thisDatabase && $entry['role'] === $role && $entry['name'] === $name) {
                return $entry['value'];
            }
        }

        return null;
    }
}
