<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

/**
 * What a statistics number is a statistic OF — the closed set of quantities this package reads
 * about a stored object.
 *
 * The set is closed on purpose, and closing it is the point rather than a side effect. Provenance
 * carried as a free string is provenance a call site can invent, misspell, or leave empty, and a
 * number whose origin is `''` is a number nobody can weigh. As an enum it is unforgeable: a source
 * outside this list is not constructible, so "what is this a count of" always has an answer, and
 * always one somebody thought about.
 *
 * **The cases name the QUANTITY, never the column.** An earlier draft of this enum spelled each
 * case as the catalog identifier it came from, which read well and put PostgreSQL and MySQL
 * vocabulary into the engine-agnostic core — the coupling the core/driver split exists to prevent,
 * and the kind that enters through a string rather than through an import. Which column answers
 * a quantity is the driver's business, and each driver already knows only its own.
 *
 * It also made the enum wrong on a point that matters. The same quantity has different precision on
 * different engines: PostgreSQL computes a relation's size by stat()ing the files while it answers,
 * so that byte count is a measurement, while MySQL derives its own from pages allocated times page
 * size, which approximates allocation rather than content — a table just emptied still reports the
 * pages it holds. A source that owned its own precision could only ever be right about one of them.
 * What survives here is the part that is true of every engine there is: a row count read out of a
 * catalog is always an estimate, because counting rows means counting rows.
 */
enum EstimateSource: string
{
    /**
     * The number of live rows an object is believed to hold.
     *
     * Always an estimate, on every engine, forever — {@see self::isAlwaysEstimated()}. A catalog
     * carries what the last statistics run left behind, and the only way to a real answer is to
     * count, which is a full scan this package will never ask a production database to perform.
     *
     * This is the number the master plan's ninth pitfall is about, and the reason this type exists:
     * a rule that compared it against a threshold would answer differently on the same schema
     * depending on when statistics were last refreshed, with no way to say so.
     */
    case RowCount = 'row_count';

    /** Bytes the object's own storage occupies, without its indexes. */
    case TableBytes = 'table_bytes';

    /** Bytes every index attached to the object occupies. */
    case IndexBytes = 'index_bytes';

    /** Bytes the object occupies in total — its storage, its indexes, and the engine's overhead. */
    case TotalBytes = 'total_bytes';

    /** Bytes a whole database or tablespace currently occupies. */
    case StorageUsedBytes = 'storage_used_bytes';

    /**
     * Bytes still available to the storage a database or tablespace sits on.
     *
     * The one quantity here that is commonly not readable at all: through SQL alone, at least one
     * major engine will not say how much room is left on the volume underneath it. That absence is
     * the reason {@see StorageHeadroom} refuses to be built degraded without a skip naming why — a
     * missing free-space number is the NORMAL state, and a normal state with no reason attached is
     * the one a reader learns to take for "there is room".
     */
    case StorageFreeBytes = 'storage_free_bytes';

    /**
     * What this source counts.
     *
     * A `match` with no default arm, deliberately: a case added without a decision raises rather
     * than inheriting a plausible-looking one, and the enum's own test walks every case so the
     * raise happens in the suite instead of in somebody's production report.
     */
    public function unit(): EstimateUnit
    {
        return match ($this) {
            self::RowCount => EstimateUnit::Rows,
            self::TableBytes, self::IndexBytes, self::TotalBytes,
            self::StorageUsedBytes, self::StorageFreeBytes => EstimateUnit::Bytes,
        };
    }

    /**
     * Whether this quantity is beyond any engine's ability to state exactly from a catalog read.
     *
     * True for the row count alone, and that single `true` carries the one refusal this type owes
     * the rest of the package: {@see Estimate::exact()} will not build one, so an estimated row
     * count cannot be relabeled as a count no matter which driver is holding it.
     *
     * False for the byte quantities does NOT mean they are always exact — it means an engine may be
     * able to measure them, and which one can is that driver's knowledge rather than the core's.
     */
    public function isAlwaysEstimated(): bool
    {
        return match ($this) {
            self::RowCount => true,
            self::TableBytes, self::IndexBytes, self::TotalBytes,
            self::StorageUsedBytes, self::StorageFreeBytes => false,
        };
    }
}
