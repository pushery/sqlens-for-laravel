<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * Who put a grant there — the difference between a decision and a shipped default.
 *
 * Without it the most obvious security rule in the suite is unusable. Every PostgreSQL database
 * carries `CONNECT`/`TEMPORARY` to PUBLIC on itself and `EXECUTE` to PUBLIC on a hundred-odd system
 * functions, out of the box, on every install that has ever existed. A rule that reported "grants to
 * PUBLIC" without this field would open with a hundred findings nobody caused and nobody can fix,
 * which is how a security tool gets switched off in its first week.
 *
 * PostgreSQL records the answer itself, in `pg_init_privs`: the ACL an object had when initdb
 * finished or when the extension that owns it was installed. So this is read rather than guessed.
 */
enum GrantOrigin: string
{
    /** Somebody granted it. The only origin a project can act on, and the only one rules judge. */
    case Project = 'project';

    /** Present since `initdb` — part of what PostgreSQL is, not of what this project did. */
    case Initdb = 'initdb';

    /**
     * Installed by an extension (`pg_init_privs.privtype = 'e'`).
     *
     * PostGIS grants `EXECUTE` on hundreds of functions; reporting those would drown the findings a
     * reader can act on, which is the same catalog-dirt problem the audit suite solves for indexes.
     */
    case Extension = 'extension';

    /**
     * The object's OWNER, whose full-privilege entry PostgreSQL materializes on the first grant.
     *
     * `pg_init_privs` does not cover it, so it arrived here as a project decision — and it is the
     * opposite of one. `relacl` is NULL until somebody grants ANYTHING; at that moment PostgreSQL
     * writes the owner's own entry into it as well, and that entry is `acldefault()` by definition:
     * every privilege the object type permits.
     *
     * Measured on PostgreSQL 18.4:
     *
     *     create table t (id int);              relacl → NULL
     *     grant select on t to public;          relacl → {me=arwdDxtm/me, =r/me}
     *     select acldefault('r', relowner);            → {me=arwdDxtm/me}
     *
     * So `SEC.PRIV.GRANT_ALL` reported the owner of EVERY table that had received any grant at all,
     * saying "holds EVERY privilege … there is no privilege escalation left to perform" about the
     * role that owns the thing. Trivially true, and exactly the noise that gets a security tool
     * switched off in its first week — which is the failure this enum exists to prevent, met again
     * on a source it did not yet know about.
     *
     * It is NOT judged, and the direction is deliberate: an owner's full access is a consequence of
     * ownership, not a grant somebody may revoke. Revoking it is not the remedy, transferring
     * ownership is — a different finding, and not this one.
     */
    case Owner = 'owner';

    /** Whether a rule should judge this grant at all. */
    public function isProjectDecision(): bool
    {
        return $this === self::Project;
    }
}
