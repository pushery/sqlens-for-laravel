<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * How a canonical statement relates to a transaction — the axis half a rule class
 * (CONCURRENTLY, lock duration, roundtrip safety) turns on. Driver-agnostic: the
 * resolver stage decides which mode applies from the migration flag, the driver's
 * DDL-transaction capability, and the transaction markers in the stream.
 *
 * `Undetermined` is a first-class, reasoned outcome — a conditional transaction in
 * PHP, an unbalanced marker, an unresolvable migration class — never a guess
 * dressed up as `None`.
 */
enum TransactionMode: string
{
    /** Runs inside the migrator's implicit transaction (the engine wraps DDL). */
    case ImplicitMigratorTransaction = 'implicit_migrator_transaction';

    /** Opens an explicit transaction itself (a BEGIN / START TRANSACTION in the stream). */
    case ExplicitTransaction = 'explicit_transaction';

    /** Runs in no transaction — outside the migrator's, and the engine does not wrap it. */
    case None = 'none';

    /** The transaction context could not be decided; the reason is carried alongside. */
    case Undetermined = 'undetermined';
}
