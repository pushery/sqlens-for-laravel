<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\MatrixEntry;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\OperationKeyMapper;
use Pushery\SQLens\Drivers\Mysql\Remediation\AlgorithmLockTemplate;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A schema-builder operation MySQL will not run online, written the one way that cannot say so.
 *
 * Laravel's MySQL grammar has no way to emit `ALGORITHM=` or `LOCK=` — verified against the
 * installed framework and pinned by a characterization test, not assumed. Those are precisely the
 * two clauses that would keep an InnoDB migration provably online, so the gap is not cosmetic: a
 * migration written through the builder takes whatever algorithm the server picks, and finds out
 * which one that was afterwards.
 *
 * ## What an explicit ALGORITHM actually buys, stated honestly
 *
 * It does not make a copying operation online. **It makes the server refuse.** `ALGORITHM=INPLACE`
 * on an operation MySQL can only do by copying fails with an error instead of silently copying the
 * table — so the deploy stops before it locks anything, rather than during. That is the whole value
 * and the finding says it in those words, because a reader who believes the clause makes the
 * operation cheap has been made more confident and no safer.
 *
 * ## The rule fires from the MATRIX, never from a list
 *
 * The trigger is: the operation's downtime class comes back as something other than `online`, and
 * the statement carries neither clause. Nothing about which operations those are is written here —
 * the matrix decides, so the rule follows a matrix revision without being edited, and cannot
 * disagree with the rules that report those same operations.
 *
 * ## Silence here means "no suggestion", not "safe"
 *
 * When the matrix cannot settle the class — an operation it does not classify, or one whose entry
 * is conditional on a table fact a static reader cannot see — this rule says nothing. That is not a
 * silent pass: the safety verdict on those statements belongs to the rules that own them, and they
 * report it. This rule only ever offers an improvement it can justify, and an improvement it cannot
 * justify is one it should not offer.
 */
final class AlgorithmLockNotExpressibleRule extends AbstractMysqlRule implements DerivesDowntimeClass, ProvidesRemediation
{
    private readonly MysqlDowntimeClassSource $downtimeClasses;

    private readonly OperationKeyMapper $operationKeys;

    /** The pinned-statement template, built once. */
    private readonly AlgorithmLockTemplate $template;

    /** The considered `none`, for the two ways the matrix declines to name a clause. */
    private readonly NoSafeSequenceTemplate $noSafeSequence;

    public function __construct(
        string $projectRoot,
        ?MysqlDowntimeClassSource $downtimeClasses = null,
        ?OperationKeyMapper $operationKeys = null,
    ) {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->operationKeys = $operationKeys ?? new OperationKeyMapper;
        $this->template = new AlgorithmLockTemplate;
        $this->noSafeSequence = new NoSafeSequenceTemplate;
    }

    /**
     * The pinned statement, with the two values read out of the matrix ENTRY rather than chosen.
     *
     * It comes through the same source the verdict does, so the suggestion and the class on the
     * finding can never come from two different resolutions of one operation. A guessed `ALGORITHM`
     * would be worse than none: `INPLACE` on an operation that cannot do it turns a slow deploy
     * into a failed one, and `COPY` on one that could have been instant buys a rewrite nobody
     * needed.
     *
     * ## Where the matrix declines, the answer is a considered `none` rather than an absence
     *
     * It used to be `null` for both of the ways that can happen, and `null` is the WRONG shape for
     * either. An absent payload says only that nobody wrote a template; here a rule has looked, has
     * flagged the statement, and has a specific thing to report about WHY it will not name a clause.
     * Those are different facts and a reader acts differently on each.
     *
     * There is exactly ONE way it can happen, and the reason the other one is absent is worth
     * recording. "The matrix has no entry" cannot reach here: the rule's own trigger is a resolved
     * matrix entry — {@see disruptiveClassOf()} asks the same source for the same key at the same
     * version, and an unresolved lookup produces an undetermined mapping, no class, and therefore no
     * finding. A branch for it would be a case this rule cannot enter, which is worse than no
     * branch: it would claim to handle something and never be executed to prove it.
     *
     * What DOES happen is an entry whose clause guarantees nothing. A handful of statements ACCEPT
     * `ALGORITHM=` and ignore it — `EXCHANGE PARTITION` takes even `ALGORITHM=COPY, LOCK=NONE`, a
     * self-contradictory pair every other statement rejects. The shipped matrix records those only
     * for partition operations, which no mapped statement kind reaches today; a revision that gave
     * a mapped operation that shape would otherwise turn this into a silent absence on a flagged
     * statement, and the `none` is what keeps it a statement instead.
     *
     * Silence remains the answer for a statement this rule does not flag at all: no finding, no
     * material. A `none` attached there would read as "SQLens examined this and gave up".
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $entry = $this->matrixEntryFor($statement);

        // No finding, no material. The two ways to arrive here are one branch on purpose: a
        // statement this rule does not flag, and — unreachably, see above — a flagged one whose
        // entry vanished. Splitting them would give the second its own line, and a line that cannot
        // be executed is one no run can prove.
        if (! $entry instanceof MatrixEntry) {
            return null;
        }

        $context = [];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->forEntry($entry, $context, $this->id(), $this->downtimeClassFor($statement))
            ?? $this->noSafeSequence->payload(
                'sqlens::messages.remediation.no_safe_sequence.clause_is_ignored',
                'sqlens::messages.remediation.no_safe_sequence.algorithm_lock_verification',
                $this->id(),
                $this->downtimeClassFor($statement),
            );
    }

    /** The matrix entry behind a statement this rule FLAGS, or null when there is none to read. */
    private function matrixEntryFor(MigrationStatementView $statement): ?MatrixEntry
    {
        if (! $this->disruptiveClassOf($statement) instanceof DowntimeClass) {
            return null;
        }

        $operation = $this->operationKeys->forKind($statement->kind);

        return $this->downtimeClasses->resolutionFor(
            (string) $operation->key,
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->entry;
    }

    public function id(): string
    {
        return 'MY.L3.ALGORITHM_LOCK_UNEXPRESSIBLE';
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /**
     * The operation's class, from the matrix — the same derivation the verdict turns on.
     *
     * My first draft left this null, reasoning that the finding is about a missing CLAUSE rather
     * than about a cost, and that the rule reporting the operation would carry the class. The
     * registry guard rejected that, and it was right: a release gate reads the FINDING, and there
     * is no guarantee another rule reports the same statement — a spatial index build, for one, is
     * reported by nothing else. A finding with no class would tell that gate nothing about what
     * deploying it does, which is exactly what the field exists to prevent.
     */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        return $this->disruptiveClassOf($statement);
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        return $this->disruptiveClassOf($statement) instanceof DowntimeClass ? $this->message() : null;
    }

    /**
     * The operation's class when it disrupts anyone, or null when there is nothing to suggest.
     *
     * One derivation, both callers, so the verdict and the class a finding carries can never come
     * from two readings of one statement. Null covers three different silences — already pinned, an
     * operation the matrix cannot place, and one it runs online — and none of them is a claim that
     * the statement is safe (see the class docblock).
     */
    private function disruptiveClassOf(MigrationStatementView $statement): ?DowntimeClass
    {
        if ($this->alreadyPinned($statement->canonical)) {
            return null;
        }

        // The KIND is what names the operation, and the kind is a canonical fact the view carries.
        // Going through the shared mapper rather than reading the SQL keeps this rule and the ones
        // that report those same operations from ever disagreeing about what a statement does.
        $operation = $this->operationKeys->forKind($statement->kind);

        if (! $operation->isResolved()) {
            return null;
        }

        $class = $this->downtimeClasses->forCandidateOperations(
            [(string) $operation->key],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;

        return $class instanceof DowntimeClass && $class->disrupts() ? $class : null;
    }

    /**
     * Whether the statement already names an algorithm or a lock level.
     *
     * A migration that reached for a raw statement to pin them has already done the thing this rule
     * asks for, and telling it to do so again is how a linter loses its reader. String literals are
     * masked so a column default spelling the clause cannot silence the rule — the direction that
     * would cost something.
     */
    private function alreadyPinned(string $canonical): bool
    {
        $masked = preg_replace("/'(?:[^']|'')*'/", "''", $canonical) ?? $canonical;

        return preg_match('/\b(?:ALGORITHM|LOCK)\s*=/i', $masked) === 1;
    }

    private function message(): string
    {
        return 'MySQL will not run this operation online, and Laravel\'s schema builder cannot say so: its MySQL '
            .'grammar has no way to emit ALGORITHM= or LOCK=, the two clauses that would pin the behavior. Written '
            .'through the builder, the statement takes whatever algorithm the server picks and you learn which one '
            .'afterwards. Issue it as a raw statement instead, naming both — for example '
            .'DB::statement(\'ALTER TABLE … , ALGORITHM=INPLACE, LOCK=NONE\') — and leave a comment saying why: raw '
            .'SQL is a deliberate exception here, not the normal way to write a migration, and the next reader has '
            .'to be able to tell those apart. Be clear about what the clause buys, though: it does NOT make a '
            .'copying operation online. It makes the server REFUSE — an operation MySQL can only do by copying '
            .'fails outright instead of silently copying the table, so the deploy stops before it locks anything '
            .'rather than in the middle of it.';
    }
}
