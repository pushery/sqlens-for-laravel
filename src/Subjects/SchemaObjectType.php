<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * The catalog object types the audit, security and deploy suites need.
 * Cut in full here, not retrofitted: Role, Grant, Setting and HbaRule are not an
 * afterthought — without them the security suite could not model its findings as
 * subjects and would build a second path.
 */
enum SchemaObjectType: string
{
    case Table = 'table';
    case Column = 'column';
    case Index = 'index';
    case Constraint = 'constraint';
    case View = 'view';
    case MaterializedView = 'materialized_view';
    case Sequence = 'sequence';

    /**
     * A user-defined type: a PostgreSQL domain or enum.
     *
     * Added when the catalog reader needed somewhere to put one, and it is not a stylistic
     * addition. An enum is the object a level-4 rule already reasons about from the migration side
     * — adding a value to one is the change that cannot be rolled back — so the audit side has to
     * be able to see which enums a database actually holds, or the two halves of that rule would be
     * looking at different worlds. MySQL has no counterpart: its `ENUM` is a column type rather
     * than a schema object, which is a difference the model states by simply never producing this
     * type on that driver.
     */
    case Type = 'type';
    case Routine = 'routine';
    /**
     * A trigger, which is the one schema object that does not own its own name.
     *
     * A trigger name is unique per TABLE, not per schema — two tables may each carry a `audit_row`,
     * and they are two objects. So its identity is the pair, and a comparison keyed on the name
     * alone would fold them into one object that appears to change every time the reading order
     * shifts.
     *
     * The two engines put the body in different places, and the model does not try to hide it. On
     * MySQL the action statement is stored inline and is the thing that drifts. On PostgreSQL the
     * trigger only NAMES a function, whose body is compared separately as a {@see self::Routine} —
     * so what drifts there is the binding: the timing, the events, and which function it calls.
     */
    case Trigger = 'trigger';

    /**
     * A scheduled event, which exists on MySQL and has no PostgreSQL counterpart at all.
     *
     * This is the only object type in the model that is genuinely one-sided, and the distinction it
     * forces is worth stating: PostgreSQL not having events is a FACT, not an unread part of the
     * catalog. So the PostgreSQL reader does not list this type, does not skip it, and produces no
     * blind spot for it — "the engine has no such object" and "I could not look" are different
     * answers, and only the second one is bad news.
     *
     * ## Most of what `information_schema.EVENTS` holds is not schema
     *
     * An event is the one catalog object that REWRITES ITS OWN ROW BY RUNNING. Measured on MySQL
     * 8.4.10 against a live scheduler: `LAST_EXECUTED` moves on every single execution, and a
     * one-shot event declared `ON COMPLETION PRESERVE` flips its own `STATUS` from `ENABLED` to
     * `DISABLED` when it fires — with nobody touching the schema.
     *
     * A reading that compared those fields would report drift against an untouched database every
     * few seconds, which is the failure the whole comparison layer exists to prevent.
     */
    case Event = 'event';
    case Policy = 'policy';
    /**
     * A namespace that holds objects — PostgreSQL's schema, and MySQL's database, which is the same
     * thing under a different word.
     *
     * It earns a case because it is a GRANT TARGET, and the most consequential one: `CREATE` on a
     * schema is what lets an account add objects at all, and a grant of it to PUBLIC applies to every
     * role the server will ever have. A grant whose target could not be named would have to be
     * reported against the table it is not about.
     */
    case Schema = 'schema';

    /**
     * The database itself — the target of `CONNECT`, `TEMPORARY` and `CREATE` grants.
     *
     * Distinct from {@see self::Schema} on PostgreSQL, where the two nest; on MySQL the reading maps
     * a database grant to this case and a table grant to {@see self::Table}, because MySQL's "schema"
     * IS its database and splitting the word would invent a level that engine does not have.
     */
    case Database = 'database';

    case Role = 'role';
    case Grant = 'grant';
    case Setting = 'setting';
    case HbaRule = 'hba_rule';
    case Extension = 'extension';

    /**
     * A collation, database-wide or explicitly created.
     *
     * Its own type rather than a flavor of `Type`, because the question asked of it is unlike any
     * other object's: not "what shape is this" but "does the version recorded when it was created
     * still match the one installed now". A drifted collation silently invalidates every index built
     * on it, so the fact travels as a first-class subject rather than as an attribute of something
     * else.
     */
    case Collation = 'collation';
}
