<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Drivers\EngineIdentity;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The answer to "can this connection's statistics be read" — a reader, or a NAMED reason there is
 * none.
 *
 * Two things must not happen at this seam, and they pull in opposite directions.
 *
 * **It must not throw.** Resolution runs inside a deploy gate, at the moment nobody has decided yet
 * whether the deploy should happen. An exception there stops the deploy without having said
 * anything about the database — the gate would be blocking on its own inability to look, which is
 * the least useful reason to block that exists.
 *
 * **It must not answer with nothing.** An empty statistics reading and a clean one are the same
 * object, so a caller that got silence would weight every finding as if the tables were small. The
 * unsupported case therefore carries a {@see CatalogSkip}, which cannot be built without a reason.
 *
 * That is why this type exists rather than a nullable return: null would satisfy the first
 * requirement and quietly break the second.
 */
final readonly class StatisticsResolution
{
    private function __construct(
        public ?StatisticsReader $reader,
        public ?CatalogSkip $skip,
    ) {}

    /** This driver reads statistics, and here is the reader. */
    public static function reader(StatisticsReader $reader): self
    {
        return new self($reader, null);
    }

    /**
     * This driver reads none, and here is why — by name, never as free text.
     *
     * The banner travels into the detail when there is one, because "unsupported" answers a
     * different question depending on what was found: a SQLite connection is a deliberate scope
     * decision, and a MariaDB one is a server somebody believes is MySQL.
     */
    public static function unsupported(string $driver, ?string $banner = null): self
    {
        return new self(null, CatalogSkip::for(
            SchemaObjectType::Database,
            $driver,
            SkipReason::UnsupportedDriver,
            self::detailFor($driver, $banner),
        ));
    }

    /** Whether a reading can happen at all. */
    public function isResolved(): bool
    {
        return $this->reader instanceof StatisticsReader;
    }

    /**
     * Why a MariaDB server is refused where a version comparison would let it through.
     *
     * Laravel puts MariaDB behind its own `mysql` driver key, and MariaDB reports a version high
     * enough to clear any MySQL floor — so a check that compared numbers would accept it and then
     * reason about MySQL 8.4 semantics MariaDB does not share. The engine's own banner is what
     * separates them, which is why {@see EngineIdentity} reads that rather than the number.
     */
    private static function detailFor(string $driver, ?string $banner): string
    {
        if ($banner !== null && EngineIdentity::isMariaDb($banner)) {
            return sprintf(
                'this connection reports "%s", which is MariaDB behind Laravel\'s mysql driver. Its '
                .'version clears every MySQL floor, so only the banner tells them apart — and MySQL '
                .'8.4 semantics do not carry over, so statistics read here would be weighed by rules '
                .'written for a different engine.',
                $banner,
            );
        }

        return sprintf(
            'the "%s" driver has no statistics reader in this build, so object sizes could not be '
            .'read. This is a named absence rather than an empty reading: no statistics and no '
            .'blockers would otherwise look alike.',
            $driver,
        );
    }
}
