<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * What a pending statement needs the migration role to be allowed to do.
 *
 * ## Why classes and not privilege names
 *
 * PostgreSQL and MySQL spell the same permission differently, and one of them does not spell it as a
 * permission at all. A derivation that produced `ALTER` on MySQL and `OWNER` on PostgreSQL would
 * have two answers to one question and no way to compare them — so the derivation answers in
 * CLASSES, and each driver's own check translates one class into what its engine calls it.
 *
 * That boundary is also what keeps `src/Deploy` free of engine knowledge, which the core-purity
 * census enforces.
 */
enum PrivilegeClass: string
{
    /** Bringing an object into existence: a table, an index, a type, a sequence. */
    case Create = 'create';

    /**
     * Changing an object that already exists.
     *
     * Distinct from {@see self::Ownership} on purpose — see that case. On MySQL this really is a
     * grantable privilege; on PostgreSQL most of what falls here is not.
     */
    case Alter = 'alter';

    /** Removing an object. Separate from `Alter` because a project may grant one and not the other. */
    case Drop = 'drop';

    /**
     * Pointing a foreign key at another table.
     *
     * Its own class because it is a permission on the REFERENCED table rather than on the one being
     * altered — a role may own the child and have nothing on the parent, and that is exactly the
     * case that fails at deploy time with a message about the wrong table.
     */
    case References = 'references';

    /**
     * Writing rows: the backfill half of a migration.
     *
     * Kept apart from the schema classes because a project that runs migrations with a
     * schema-only role discovers the difference at the moment the backfill runs, halfway through.
     */
    case Write = 'write';

    /**
     * Being the OWNER of the object.
     *
     * Its own class rather than a kind of `Alter`, and this is the distinction the whole enum exists
     * for. On PostgreSQL, `ALTER TABLE` cannot be granted: it requires ownership, and no `GRANT`
     * produces it. A model that filed it as a privilege would let a check report "grant ALTER on
     * that table" — advice that cannot be followed, given to somebody in a deploy window.
     */
    case Ownership = 'ownership';
}
