<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Database\Connection;
use PDOException;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\SessionDefense;
use Throwable;

/**
 * A bounded, read-only session for reading a live catalog — and the proof that it is one.
 *
 * ## The verification is the point
 *
 * Applying the defense is easy; being sure it took is not. Measured while building this: on
 * PostgreSQL a session-wide read-only flag reported itself as set and writes went through anyway.
 * A layer whose whole promise is "this tool cannot write to your database" cannot rest that promise
 * on a `SET` nobody checked — that is the silent green this package refuses everywhere else, aimed
 * at itself.
 *
 * So {@see open()} attempts a write and REQUIRES the refusal. If the write succeeds, the session is
 * not sealed and the read does not happen: an unsealed reader is a worse outcome than no reading.
 *
 * ## What it never does
 *
 * No lock, no DDL, no DML — the write probe is the single exception, and it is expected to fail.
 * The session bounds itself before the first catalog query, so a reader pointed at a busy
 * production instance can never be the incident it was sent to look for.
 */
final class ReaderSession
{
    /** The savepoint the write probe runs under. Named, so a stray one is traceable to this code. */
    private const string PROBE_SAVEPOINT = 'sqlens_read_only_probe';

    /** What the last write probe proved the seal rests on, or null while no probe has run. */
    private ?SealedBy $sealedBy = null;

    public function __construct(
        private readonly Connection $connection,
        private readonly SessionDefense $defense,
        private readonly SessionBudget $budget,
    ) {}

    /**
     * A session on the SAME connection, bounded more tightly.
     *
     * The one way a caller changes what this session costs, and it exists so the deploy readers can
     * run under their own budget without a second session factory beside the one that already knows
     * how to seal an engine. Same connection, same defense, tighter numbers — which is the whole
     * of "no second code path" applied to the thing most likely to grow one.
     *
     * A new instance rather than a mutation: the seal bookkeeping is per-session state, and handing
     * back a session that had already proven itself under different bounds would be reporting a
     * proof that was made about something else.
     */
    public function withBudget(SessionBudget $budget): self
    {
        return new self($this->connection, $this->defense, $budget);
    }

    /** The bounds this session runs under — what a caller narrows from. */
    public function budget(): SessionBudget
    {
        return $this->budget;
    }

    /**
     * Whether the read-only guarantee rests on the account's grants rather than on the session.
     *
     * Worth reporting: an audit run this way cannot be made to write even by a bug in this package,
     * which is a stronger statement than the one the seal usually makes.
     */
    public function sealedByPrivilege(): bool
    {
        return $this->sealedBy === SealedBy::Privilege;
    }

    /**
     * What the read-only guarantee rests on, as the write probe proved it, or null before any read.
     *
     * Null is an answer of its own. A session that has not read has proven nothing, and reporting
     * {@see SealedBy::Session} for it would state a seal from configuration rather than from the
     * refusal that establishes it.
     */
    public function sealedBy(): ?SealedBy
    {
        return $this->sealedBy;
    }

    /**
     * The source connection this session reads — the instance every finding from it is about.
     *
     * The session is the only object that knows it: the reader is handed a session, not a name, and
     * a rule sees neither. Asking here means no caller has to remember to pass an instance name
     * alongside the connection it already passed.
     */
    public function instance(): string
    {
        return ReaderConnectionFactory::sourceOf($this->connection);
    }

    /**
     * Bound the session, seal it read-only, PROVE the seal, and run the read inside the transaction.
     *
     * @template T
     *
     * @param  callable(Connection): T  $read
     * @return T
     *
     * @throws UnsealedReaderSession when the write probe was NOT refused
     */
    #[RawSql(reason: 'transaction control -- BEGIN and SET TRANSACTION READ ONLY. The builder has no verb for either, and this is the seal every reader in the package stands on')]
    public function read(callable $read): mixed
    {
        foreach ($this->defense->sessionStatements($this->budget) as $statement) {
            $this->connection->statement($statement);
        }

        foreach ($this->defense->preTransactionStatements() as $statement) {
            $this->connection->statement($statement);
        }

        // Through Laravel's own `beginTransaction()`, never a raw `BEGIN TRANSACTION READ ONLY`
        // over `statement()` — and that is a correctness requirement, not a style choice.
        //
        // `LostConnectionDetector` lists `SQLSTATE[25006]: Read only sql transaction: 7` among the
        // strings that mean the connection died, and `Connection::handleQueryException()` rethrows
        // only while `transactions >= 1`. Open the transaction where Laravel cannot see it, and a
        // write this session refuses is read as a dead connection: the framework RECONNECTS and
        // RUNS THE STATEMENT AGAIN, outside any transaction, where nothing refuses it.
        //
        // The statement that would be retried is the seal's own write probe below. The package
        // would write into the database it promises never to write to — and only then report that
        // the session is not sealed. Measured against a real server in
        // tests/Postgres/ReaderSessionEffectiveTest.php, which also measures that MySQL does NOT
        // retry, because the detector's needle is PostgreSQL's wording rather than the SQLSTATE.
        $this->connection->beginTransaction();

        try {
            foreach ($this->defense->inTransactionStatements($this->budget) as $statement) {
                $this->connection->statement($statement);
            }

            $this->assertSealed();

            return $read($this->connection);
        } finally {
            // Always a rollback, never a commit. A read transaction has nothing to commit, and
            // rolling back is the one ending that cannot accidentally persist anything.
            $this->connection->rollBack();
        }
    }

    /** How long a whole reading may take before it reports that it took too long. */
    public function readBudgetMs(): int
    {
        return $this->budget->readBudgetMs;
    }

    /**
     * Whether a throwable is this session's own budget firing rather than a fault in the catalog.
     *
     * The distinction decides what a reader reports: a timeout is a NAMED undetermined — the read
     * was bounded and the bound was reached — while anything else is an unexpected error that has
     * to carry its code. Collapsing the two would file the tool's own self-restraint as a database
     * fault.
     */
    public function isOwnTimeout(Throwable $error): bool
    {
        $state = self::sqlStateOf($error);

        // The DRIVER CODE travels with the SQLSTATE, because on MySQL the SQLSTATE alone says
        // nothing: every timeout AND every lost connection arrives as the general `HY000`. Read
        // here rather than inside the defense so the extraction stays beside `sqlStateOf()`, which
        // already knows how a driver error is wrapped on the way up.
        return $state !== null && $this->defense->isTimeout($state, self::driverCodeOf($error));
    }

    /**
     * The driver's own error number, walking the chain the way {@see self::sqlStateOf()} does.
     *
     * Both the wrapped and the bare shape: Laravel puts the `PDOException` behind a
     * `QueryException`, and several catalog readers catch the PDO error directly. A lookup that
     * only knew the wrapped one returned null for half the callers — and null, on MySQL, means
     * every timeout reads as a database failure.
     */
    public static function driverCodeOf(Throwable $error): ?int
    {
        for ($current = $error; $current instanceof Throwable; $current = $current->getPrevious()) {
            if ($current instanceof PDOException && isset($current->errorInfo[1]) && is_int($current->errorInfo[1])) {
                return $current->errorInfo[1];
            }
        }

        return null;
    }

    /** The SQLSTATE a throwable carries, or null when it is not a database error at all. */
    public static function sqlStateOf(Throwable $error): ?string
    {
        for ($current = $error; $current instanceof Throwable; $current = $current->getPrevious()) {
            if ($current instanceof PDOException && is_string($current->getCode()) && $current->getCode() !== '') {
                return $current->getCode();
            }
        }

        return preg_match('/SQLSTATE\[(\w+)\]/', $error->getMessage(), $matches) === 1 ? $matches[1] : null;
    }

    /**
     * Attempt a write and require the refusal — inside a SAVEPOINT, which is not a detail.
     *
     * On PostgreSQL a failed statement ABORTS the whole transaction: every command after it is
     * refused with `25P02` until the block ends. So a probe that simply failed would poison the very
     * transaction the read was about to happen in — the seal would be proven and the reading would
     * then be impossible. Found by the effectiveness test against a real server, which is what that
     * test is for; the unit tests could not have shown it, because the failure is a property of the
     * server's transaction semantics rather than of the statements.
     *
     * The savepoint is rolled back either way, so the probe leaves the transaction exactly as it
     * found it. MySQL does not abort on a failed statement, but it takes the same standard SQL, and
     * one path for both engines is worth more here than saving a round trip on one of them.
     *
     * A write that SUCCEEDS is the failure case, and it throws rather than degrading: a reader that
     * knows it is not read-only and reads anyway has given up the only guarantee it offers.
     */
    #[RawSql(reason: 'proves the read-only seal by attempting a write inside a savepoint and requiring it to fail; issuing statements a builder would refuse to model is the entire point')]
    private function assertSealed(): void
    {
        // Cleared before the probe, so a proof that fails cannot leave an earlier one standing.
        $this->sealedBy = null;

        $this->connection->statement('SAVEPOINT '.self::PROBE_SAVEPOINT);

        try {
            $this->connection->statement($this->defense->writeProbe());
        } catch (Throwable $refusal) {
            $this->connection->statement('ROLLBACK TO SAVEPOINT '.self::PROBE_SAVEPOINT);

            $state = self::sqlStateOf($refusal);

            if ($state !== null && $this->defense->isReadOnlyRefusal($state)) {
                $this->sealedBy = SealedBy::Session;

                return;
            }

            if ($state !== null && $this->defense->isPrivilegeRefusal($state)) {
                // Sealed by the GRANT rather than by the session flag. Recorded, not conflated:
                // both prove this session cannot write, and the privilege proof is the more durable
                // of the two — but a caller asking "what is this guarantee resting on?" deserves an
                // answer, and folding them together would remove the question.
                $this->sealedBy = SealedBy::Privilege;

                return;
            }

            throw UnsealedReaderSession::refusedForTheWrongReason($state ?? '(no SQLSTATE)', $refusal);
        }

        // The probe went through. Undo whatever it made before saying so — the failure is that the
        // session accepts writes, and leaving one behind while reporting it would be absurd.
        $this->connection->statement('ROLLBACK TO SAVEPOINT '.self::PROBE_SAVEPOINT);

        throw UnsealedReaderSession::acceptedAWrite();
    }
}
