<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * A role privilege attribute, in the one vocabulary both engines are mapped into.
 *
 * PostgreSQL states these as boolean columns on `pg_roles`; MySQL states the equivalent powers as
 * global privileges in `mysql.user`. A rule that had to know which engine it was looking at would be
 * two rules, and the second one is always the one nobody writes — so the mapping happens once, here,
 * at the edge.
 *
 * The set is deliberately the SHARED, security-relevant surface rather than every flag either engine
 * has. An attribute nothing can reason about is a field to keep in sync for no verdict.
 */
enum RoleAttribute: string
{
    /** Total authority over the instance — PG `rolsuper`, MySQL `Super_priv`. */
    case Superuser = 'superuser';

    /** May create and alter other roles — PG `rolcreaterole`, MySQL `Create_user_priv`. */
    case CreateRole = 'create_role';

    /** May create databases — PG `rolcreatedb`, MySQL `Create_priv` at the global scope. */
    case CreateDatabase = 'create_database';

    /**
     * Bypasses row-level security — PG `rolbypassrls`, and the reason an RLS audit can be
     * technically correct and practically void.
     *
     * MySQL has no equivalent, and the absence is a real difference rather than a gap: a MySQL role
     * simply never carries it, so a rule asking for it gets `false` on MySQL because the engine has
     * no such power to hold, not because nobody read it.
     */
    case BypassRls = 'bypass_rls';

    /** May open a session at all — PG `rolcanlogin`, MySQL: every account in `mysql.user` may. */
    case Login = 'login';

    /** May start replication — PG `rolreplication`, MySQL `Repl_slave_priv`. */
    case Replication = 'replication';

    /**
     * Inherits the privileges of roles it is a member of without an explicit `SET ROLE` — PG
     * `rolinherit`.
     *
     * It is in the shared vocabulary because it changes what a membership MEANS: a non-inheriting
     * member of a powerful role holds that power only after asking for it, which is a materially
     * different exposure from holding it always.
     *
     * On MySQL it is not read, and a role there never carries it. The engine has an equivalent,
     * `activate_all_roles_on_login`, but that is a server setting rather than an account attribute,
     * and the reader does not ask for it. Unlike `BypassRls`, the absence on MySQL is a gap in the
     * reading rather than in the engine, so a rule that judges this attribute there has to read the
     * setting first, and say so where it could not, before its verdict means anything.
     */
    case Inherit = 'inherit';
}
