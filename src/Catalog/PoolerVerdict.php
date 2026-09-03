<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * Whether the session an audit reads through is multiplexed across server backends.
 *
 * ## What a transaction pooler does to a reading
 *
 * PgBouncer in transaction mode — and ProxySQL doing the same for MySQL — hands each statement
 * whichever server connection is free. Two statements one line apart in this package's code can
 * therefore land on two different backends, and neither of them knows it.
 *
 * That is fine for an application, which is why the topology exists. It is not fine for an audit,
 * and the damage is specific rather than general: **the schema is the same on every backend, so
 * catalog findings are unaffected — but session state is not.** SQLens' own defenses
 * (`statement_timeout`, `lock_timeout`) may not be attached to the backend that runs the next
 * query; `inet_server_addr()` names whichever backend answered; and the global-versus-session
 * distinction the whole server-baseline family rests on becomes meaningless, because the "session"
 * value came from one machine and the "global" value possibly from another.
 *
 * The result is the most dangerous shape a wrong answer can take: plausible values that do not
 * belong together, reported with no indication that anything is unusual.
 *
 * ## Why three values, and why the bias is the opposite of the shadow probe's
 *
 * The shadow captor asks the same question and errs toward *not pooled*, because a false positive
 * there blocks a working connection while a false negative surfaces as a clear error when a template
 * operation fails.
 *
 * The audit's asymmetry runs the other way. A false negative here produces a report that looks
 * exactly like a good one, and nothing ever fails to reveal it. So "I could not tell" is its own
 * answer and is never rounded down to {@see self::None}.
 */
enum PoolerVerdict: string
{
    /** The session keeps one backend. Settings read through it belong to one server. */
    case None = 'none';

    /**
     * The session is multiplexed — measured, not guessed.
     *
     * Every rule whose subject is the INSTANCE reports `undetermined` from here. Catalog rules are
     * untouched: a schema is the same on every backend of one database.
     */
    case Transaction = 'transaction';

    /**
     * The probe could not answer — it errored, or the configuration says pooler while the behavior
     * says otherwise and neither side is conclusive.
     *
     * Reported, never silently treated as {@see self::None}. Whoever reads the report has to be able
     * to tell "SQLens checked and this is a direct connection" from "SQLens could not check".
     */
    case Undetermined = 'undetermined';
}
