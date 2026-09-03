<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * The algorithm InnoDB runs a DDL operation under, in ascending cost.
 *
 * INSTANT changes only metadata and returns at once; INPLACE works within the existing
 * table and lets other sessions keep writing; COPY rewrites the whole table. Which one an
 * operation gets is the fact the online-DDL matrix records, and it is the largest single
 * input to a migration's downtime_class.
 *
 * ## Why there is a fourth case that names no algorithm
 *
 * For a set of statements the `ALGORITHM` / `LOCK` clause does not decide anything, and
 * leaving those out of the matrix would have been the wrong kind of silence: an operation
 * missing from the matrix reads as "not yet classified", when in fact it is classified and the
 * answer is that this axis does not apply. {@see NotApplicable} records that as a value.
 *
 * Measured on 8.4.10, it happens in two shapes that look nothing alike from the outside:
 *
 * - **The grammar refuses the clause.** `ALTER TABLE … REMOVE PARTITIONING` and
 *   `ALTER TABLE … PARTITION BY …` reject any `ALGORITHM=` or `LOCK=` with error 1064, in the
 *   same clause position where every other `ALTER TABLE` accepts it. There is nothing to
 *   record because the clause cannot be written.
 * - **The clause parses and is ignored.** `EXCHANGE PARTITION` accepts every value, including
 *   `ALGORITHM=COPY, LOCK=NONE` — a self-contradictory pair every other statement rejects with
 *   error 1846 ("COPY algorithm requires a lock"). Nothing is validated, so nothing written
 *   there means anything.
 *
 * The second shape is the dangerous one and the reason this is a value rather than a comment:
 * a migration that says `LOCK=NONE` on an exchange gets no error and no guarantee, which is
 * exactly the silent green the package exists to catch.
 *
 * When this case applies, the class still comes from the two axes the clause never owned —
 * whether the operation rebuilds the table and whether writes flow while it runs — both of
 * which are measured directly rather than read off the clause. See {@see DowntimeClassMapper}.
 */
enum OnlineDdlAlgorithm: string
{
    case Instant = 'instant';
    case Inplace = 'inplace';
    case Copy = 'copy';
    case NotApplicable = 'not_applicable';
}
