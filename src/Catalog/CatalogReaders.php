<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\CatalogReader;
use Pushery\SQLens\Contracts\InstanceIdentityReader;
use Pushery\SQLens\Contracts\PoolerReader;
use Pushery\SQLens\Contracts\SecurityReader;
use Pushery\SQLens\Contracts\ServerSettingsReader;
use Pushery\SQLens\Contracts\SettingCrossFactCollector;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Tests\Feature\Catalog\ReaderSurfaceCensusTest;

/**
 * The three readers an audit needs, over ONE session.
 *
 * They are handed out together rather than resolved separately because they must share a session:
 * "this audit opened exactly one connection" is a promise the package makes, and two independently
 * built readers would each open their own. Sharing also makes the pairing true rather than
 * coincidental — the identity a run reports is the identity of the session the catalog came from,
 * which is the only version of that sentence worth printing in a report header.
 */
final readonly class CatalogReaders
{
    public function __construct(
        public CatalogReader $catalog,
        public InstanceIdentityReader $identity,
        /**
         * The server's own configuration.
         *
         * Third rather than first because it arrived last, and it shares the session for the same
         * reason the other two do: a settings reading taken over a second connection would describe
         * a session this run never used, and on MySQL that is not academic — Laravel installs
         * per-connection values, so a second connection genuinely answers differently.
         */
        public ServerSettingsReader $settings,
        /**
         * What this driver can measure BESIDE its settings, or null when it measures nothing.
         *
         * Nullable rather than a null-object because "this engine collects no cross-facts yet" is a
         * real and temporary state, and a no-op implementation per driver would be machinery whose
         * only caller is the absence of machinery.
         */
        public ?SettingCrossFactCollector $crossFacts = null,
        /**
         * Establishes whether the session is multiplexed across backends.
         *
         * Optional because it is the one reader that cannot use {@see ReaderSession} — its answer is
         * only observable outside a transaction — so a driver without one is a real state rather
         * than a gap, and a run without one reports the topology as undetermined rather than as
         * direct.
         */
        public ?PoolerReader $pooler = null,
        /**
         * What this driver can read about the server's own security state, or null when it reads
         * nothing yet.
         *
         * Over the same session as the rest, for the reason the whole class exists: a security reading
         * taken on a second connection would describe a session this run never used, and on MySQL that
         * is not academic — the account a reading connects as decides what `mysql.user` answers, so two
         * connections can genuinely disagree about how many accounts a server has.
         *
         * Nullable rather than a null-object: "this driver has no security reader yet" is a real,
         * temporary state, and a no-op per driver would be machinery whose only caller is the absence
         * of machinery.
         */
        public ?SecurityReader $security = null,
        /**
         * How big the objects a finding names are, or null when this driver reads no statistics.
         *
         * It travels here rather than through a factory of its own, and that is the whole of the
         * deploy suite's resolution story: one registration point, one session, one place where a
         * driver key becomes a set of readers. A second mechanism beside this one would be free to
         * disagree with it about which driver answers — and it would disagree quietly, because both
         * would look right in isolation.
         *
         * The session sharing matters as much here as anywhere else. A statistics reading taken on
         * a second connection could be pointed at a different database (MySQL's "schema" IS the
         * connection's database), so the sizes would describe a server the rest of the run never
         * looked at.
         *
         * Nullable for the reason the two above are: a driver without one is a real state, and a
         * caller that finds null reports a NAMED undetermined rather than an empty reading — see
         * {@see CatalogReaderFactory::supports()}. An empty reading is the one answer that must
         * never be possible, because "no statistics" and "no blockers" read alike.
         */
        public ?StatisticsReader $statistics = null,
        /**
         * What the server is doing right now, or null when this driver reads no activity.
         *
         * It travels beside the statistics reader for the same reason that one does: the
         * registration IS the census entry. A reader resolved by a second mechanism would be
         * invisible to {@see ReaderSurfaceCensusTest},
         * and its statements would go unchecked — which is the one thing a reader that promises to
         * take no locks must not be.
         *
         * The shared session matters most of all here. Live activity is a property of the moment
         * and of the connection: a reading on a second connection would describe a different
         * session's view of the server, and on MySQL a different account's — so a blocker the run
         * is about could be invisible to the reading meant to find it.
         *
         * Nullable for the reason the others are, and the null is louder here: a caller that finds
         * one reports a NAMED undetermined, because an empty activity reading and a quiet server
         * are the same object, and "nothing is blocking" is the conclusion a deploy gate must never
         * reach by accident.
         */
        public ?ActivityReader $activity = null,
    ) {}
}
