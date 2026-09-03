<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Catalog\Statistics\StatisticsResolution;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Drivers\EngineIdentity;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The answer to "can this connection's live activity be read" — a reader, or a NAMED reason there
 * is none.
 *
 * The twin of {@see StatisticsResolution}, and it exists as its
 * own type rather than a shared one because the two answer differently at the only place that
 * matters: what a caller does wrong when it gets silence. Statistics silence makes a gate weigh
 * every finding as if the tables were small. Activity silence makes it conclude that nothing is
 * blocking — which is the more dangerous of the two, because it is the reading a deploy is waiting
 * on.
 *
 * Both requirements from the statistics half apply here unchanged, and they pull opposite ways.
 *
 * **It must not throw.** Resolution runs inside a deploy gate, before anyone has decided whether
 * the deploy should happen. An exception there stops it without having said anything about the
 * database — blocking on its own inability to look.
 *
 * **It must not answer with nothing.** An empty activity reading and a quiet server are the same
 * object. The unsupported case therefore carries a {@see CatalogSkip}, which cannot be built
 * without a reason. Null would satisfy the first requirement and quietly break the second.
 */
final readonly class ActivityResolution
{
    private function __construct(
        public ?ActivityReader $reader,
        public ?CatalogSkip $skip,
    ) {}

    /** This driver reads live activity, and here is the reader. */
    public static function reader(ActivityReader $reader): self
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
        return $this->reader instanceof ActivityReader;
    }

    /**
     * Why a MariaDB server is refused where a version comparison would let it through.
     *
     * Laravel puts MariaDB behind its own `mysql` driver key, and MariaDB reports a version high
     * enough to clear any MySQL floor — so a check that compared numbers would accept it and then
     * reason about MySQL 8.4 semantics MariaDB does not share. That is not academic for this
     * reader: MariaDB's `performance_schema` lock views differ from MySQL's, so a wait chain read
     * here would be assembled by a join written for a different engine.
     */
    private static function detailFor(string $driver, ?string $banner): string
    {
        if ($banner !== null && EngineIdentity::isMariaDb($banner)) {
            return sprintf(
                'this connection reports "%s", which is MariaDB behind Laravel\'s mysql driver. Its '
                .'version clears every MySQL floor, so only the banner tells them apart — and its '
                .'lock views differ from MySQL 8.4\'s, so a wait chain read here would be assembled '
                .'by a join written for a different engine.',
                $banner,
            );
        }

        return sprintf(
            'the "%s" driver has no activity reader in this build, so nothing could be read about '
            .'what the server is doing right now. This is a named absence rather than an empty '
            .'reading: an unread server and a quiet one would otherwise look alike, and "nothing is '
            .'blocking" is exactly the conclusion a deploy gate must not reach by accident.',
            $driver,
        );
    }
}
