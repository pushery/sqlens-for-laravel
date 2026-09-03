<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;

/**
 * The three-valued answer to "which accounts does this server have".
 *
 * The list alone would be the second-worst thing this package could return: an empty one reads
 * exactly like a server with no accounts, and a truncated one exactly like a small server. So the
 * reading carries its own completeness and the skips that explain it, and a consumer cannot get at
 * the roles without having been handed the caveat.
 *
 * Measured on PostgreSQL 18 and MySQL 8.4, the two
 * engines fail here in opposite shapes and BOTH shapes end up in this type:
 *
 * - PostgreSQL refuses `pg_authid` with `42501` while `pg_roles` answers in full — a complete SET of
 *   partial OBJECTS.
 * - MySQL refuses `mysql.user` with `1142` and offers nothing in its place — an unreadable set, which
 *   is `partial` with an empty list rather than `complete` with one.
 */
final readonly class RoleReading
{
    /**
     * @param  list<RoleObject>  $roles  sorted by identity
     * @param  list<CatalogSkip>  $skips  every reason something is missing; empty only when complete
     */
    private function __construct(
        public array $roles,
        public CatalogCompleteness $completeness,
        public array $skips,
    ) {}

    /**
     * A reading that saw the whole account list.
     *
     * Individual roles may still be partial — that is their own field, and the common case on a
     * managed database — so "complete" here means the SET is complete, nothing more.
     *
     * @param  list<RoleObject>  $roles
     */
    public static function complete(array $roles): self
    {
        return new self(self::sorted($roles), CatalogCompleteness::Complete, []);
    }

    /**
     * A reading that is missing something, with the skips that say what.
     *
     * There is no `partial()` without skips: the skip list is how a reader states what it did not get,
     * and a partial reading with an empty one would be a caveat nobody can act on. {@see CatalogSkip}
     * already refuses to exist without a reason, so the guarantee travels the whole way down.
     *
     * @param  list<RoleObject>  $roles  whatever WAS read — often empty, sometimes not
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function partial(array $roles, array $skips): self
    {
        return new self(self::sorted($roles), CatalogCompleteness::Partial, $skips);
    }

    public function isComplete(): bool
    {
        return $this->completeness === CatalogCompleteness::Complete;
    }

    /**
     * The accounts holding at least one dangerous attribute — the question most rules here start
     * from, asked once so the definition cannot drift between them.
     *
     * @return list<RoleObject>
     */
    public function privileged(): array
    {
        return array_values(array_filter($this->roles, static fn (RoleObject $role): bool => $role->isPrivileged()));
    }

    /**
     * @param  list<RoleObject>  $roles
     * @return list<RoleObject>
     */
    private static function sorted(array $roles): array
    {
        usort($roles, static fn (RoleObject $a, RoleObject $b): int => $a->sortKey() <=> $b->sortKey());

        return $roles;
    }
}
