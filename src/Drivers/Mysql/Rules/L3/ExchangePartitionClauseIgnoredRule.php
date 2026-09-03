<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3;

use Override;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * An `ALGORITHM=` or `LOCK=` clause on an `EXCHANGE PARTITION`, which MySQL parses and discards.
 *
 * ## The measurement, because the claim is the whole rule
 *
 * `ALGORITHM=COPY` together with `LOCK=NONE` is a contradiction: copying requires a lock, and the
 * server says so. Measured on 8.4.10, one statement at a time, on a fresh partitioned table:
 *
 * | Statement | Server |
 * |---|---|
 * | `ALGORITHM=COPY, LOCK=NONE, EXCHANGE PARTITION p0 WITH TABLE t` | **accepted** |
 * | `ALGORITHM=COPY, LOCK=NONE, DROP PARTITION p1` | refused, 1846 |
 * | `ALGORITHM=COPY, LOCK=NONE, ADD COLUMN c INT NULL` | refused, 1846 |
 * | `ALGORITHM=COPY, LOCK=NONE, ADD INDEX iv (v)` | refused, 1846 |
 *
 * Every neighboring statement validates the clause and rejects the contradiction with
 * *"LOCK=NONE is not supported. Reason: COPY algorithm requires a lock."* Only this one takes it.
 * That is the proof that the clause is not checked here — it is parsed and thrown away.
 *
 * ## Why that is worth a rule rather than a footnote
 *
 * It is the exact failure this package exists to name: **a promise shaped like a promise that is
 * not one.** Somebody writes `LOCK=NONE` because they want availability. They get no error and no
 * guarantee, and on any other statement the server would have argued back. This one silence is
 * indistinguishable from agreement.
 *
 * It matters more than it looks, because the operation's real cost sits somewhere the clause never
 * addressed: by default MySQL validates EVERY row of the incoming table against the partition
 * definition, and the table is not writable while that scan runs. Somebody who believes `LOCK=NONE`
 * protects them is wrong twice — the clause does nothing, and the thing they were worried about is
 * real.
 *
 * ## `WITHOUT VALIDATION` is not the reassurance it looks like
 *
 * It removes the scan and with it the guarantee: a row that does not belong in the partition lives
 * there afterwards anyway, and the table's own definition then lies about its contents. The finding
 * mentions it as a trade, never as the cheaper option — recommending it to make a lint finding go
 * away would swap an availability cost for a correctness one, silently.
 *
 * ## Read from the text, and that is the honest reason
 *
 * Its sibling {@see AlgorithmLockNotExpressibleRule} keys on the statement KIND and lets the matrix
 * decide. This one cannot: there is no `exchange_partition` kind for the canonicalizer to produce,
 * which is precisely why the operation has been invisible to the package and to its users. The
 * downtime class still comes from the matrix entry `mysql.partition.exchange_partition` — the
 * classification is not restated here, only the recognition is.
 */
final class ExchangePartitionClauseIgnoredRule extends AbstractMysqlRule implements DerivesDowntimeClass, ProvidesRemediation
{
    /** The matrix entry that owns this operation's cost. Recognition is local; classification is not. */
    private const string OPERATION = 'exchange_partition';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The considered `none` — the clause is accepted here and ignored, so there is nothing to pin. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none`, and it shares its reason with the clause rule for a reason of its own.
     *
     * This statement ACCEPTS `ALGORITHM=` and `LOCK=` and does nothing with them — it takes even
     * `ALGORITHM=COPY, LOCK=NONE`, a self-contradictory pair every other statement rejects. So the
     * fix is not a better clause, it is knowing that no clause here means anything, and pinning one
     * would hand somebody a guarantee the server never makes.
     *
     * `MY.L3.ALGORITHM_LOCK_UNEXPRESSIBLE` answers the same `clause_is_ignored` reason when the
     * matrix hands it an entry of this shape. One reason, two rules, because it is one fact — a
     * second wording would drift from this one the first time either was touched.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.clause_is_ignored',
            'sqlens::messages.remediation.no_safe_sequence.algorithm_lock_verification',
            $this->id(),
            $this->downtimeClassFor($statement),
        );
    }

    public function id(): string
    {
        return 'MY.L3.EXCHANGE_PARTITION_CLAUSE_IGNORED';
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        return $this->applies($statement->canonical) ? $this->exchangeClass($statement) : null;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        return $this->applies($statement->canonical) ? $this->message($statement) : null;
    }

    /**
     * Whether this statement exchanges a partition AND names a clause the server will discard.
     *
     * Both halves are required. An exchange without the clause has made no promise to break, and a
     * clause on any other partition operation is honored — reporting either would be a false
     * positive on a statement somebody wrote correctly.
     */
    private function applies(string $canonical): bool
    {
        $masked = $this->withoutStringLiterals($canonical);

        return preg_match('/\bEXCHANGE\s+PARTITION\b/i', $masked) === 1
            && preg_match('/\b(?:ALGORITHM|LOCK)\s*=/i', $masked) === 1;
    }

    /**
     * The operation's cost, from the matrix.
     *
     * A finding with no downtime class tells a release gate nothing about what deploying it does,
     * and no other rule reports this statement — there is no kind for one to key on.
     */
    private function exchangeClass(MigrationStatementView $statement): ?DowntimeClass
    {
        return $this->downtimeClasses->forCandidateOperations(
            [self::OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;
    }

    private function message(MigrationStatementView $statement): string
    {
        $clause = preg_match('/\bLOCK\s*=/i', $this->withoutStringLiterals($statement->canonical)) === 1
            ? 'LOCK'
            : 'ALGORITHM';

        return sprintf(
            'This EXCHANGE PARTITION names %s=, and MySQL parses that clause here without acting on it. On every '
            .'other ALTER TABLE the server checks it — ALGORITHM=COPY with LOCK=NONE is refused with error 1846 '
            .'on ADD COLUMN, ADD INDEX and DROP PARTITION alike, and accepted here. So the clause is a promise '
            .'nothing kept, and the silence reads exactly like agreement. Remove it, and decide the real question '
            .'instead: by default every row of the incoming table is validated against the partition definition '
            .'and the table does not accept writes while that runs. WITHOUT VALIDATION removes the scan and the '
            .'guarantee together — a row that does not belong in the partition then lives there anyway — so it is '
            .'a trade to make deliberately, not a way to make this finding go away.',
            $clause,
        );
    }

    /**
     * The statement with its string literals blanked.
     *
     * A column default or an inserted value spelling `LOCK=` must not decide a rule about clauses,
     * in either direction — it could silence this one, and it could invent a finding on a statement
     * that never named a clause at all.
     */
    private function withoutStringLiterals(string $canonical): string
    {
        return preg_replace("/'(?:[^']|'')*'/", "''", $canonical) ?? $canonical;
    }
}
