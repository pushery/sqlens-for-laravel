<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TransactionMode;
use Pushery\SQLens\Capture\ValueOrigin;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Security\OriginBinding;

/**
 * Everything a lint rule is allowed to reason about, and nothing more.
 *
 * A rule receives THIS, never the migration subject and never the raw grammar
 * output. That boundary is the defense against grammar drift restated at the point
 * it matters: the fields here are the CANONICAL facts — the normalized statement
 * string, what the statement does ({@see StatementKind}), what it acts on
 * ({@see StatementTarget}s from the classification stage), and what the surrounding
 * migration does ({@see MigrationContext}). There is deliberately no accessor for
 * the raw SQL, the source file, or the migration class: a rule that matched on
 * Laravel's formatting would break the day the framework changed a space, and a rule
 * that matched on a file name would be a different kind of brittle.
 *
 * The classification is nullable because a statement the driver could not classify
 * reaches a rule unclassified rather than being dropped — a rule that needs the kind
 * or a target simply finds none and stays silent, which is the correct three-valued
 * behavior, never a guess.
 */
final readonly class MigrationStatementView
{
    use SelectsStatementTargets;

    /** @param  list<StatementTarget>  $targets */
    public function __construct(
        public string $canonical,
        public ?StatementKind $kind,
        public array $targets,
        public MigrationContext $migration,
        /**
         * This statement's own position in the migration — its capture sequence, the
         * same index the entries of {@see MigrationContext::$statements} carry. A rule
         * that walks the ordered stream to find, say, the first strong-lock statement
         * uses this to tell whether IT is that statement and so should carry the once-
         * per-migration finding. It is a canonical fact about the statement (where it
         * sits), never raw grammar or provenance.
         */
        public int $statementIndex,
        /**
         * Whether this statement runs inside a transaction — the migration's own
         * `$withinTransaction`, which Laravel wraps `up()` in by default. It is a
         * canonical fact about how the statement executes, not raw grammar or
         * provenance, and it is what a rule like "CONCURRENTLY cannot run in a
         * transaction" turns on.
         */
        public bool $withinTransaction = true,
        /**
         * What the canonicalization RESOLVED the transaction context to, or null when the
         * statement never went through it.
         *
         * `$withinTransaction` above is the migrator's own flag and only ever yes/no; the
         * resolver has a third answer. An explicit transaction opening inside the migrator's,
         * an unbalanced marker, a driver declaring no transaction control — each leaves the
         * context genuinely unknown, and flattening that to "no" is how a lock-hygiene rule
         * ends up silent on the statement it was least able to judge.
         */
        public ?TransactionMode $transactionMode = null,
        /**
         * The server version the run reasons about, whole — a detected version, an
         * assume_server_version pin, or a named "could not determine".
         *
         * It is here because a rule may consult a version-WINDOWED data source (MySQL's
         * online-DDL matrix is the one), and such a source cannot answer without a version.
         * When there is none, the run's own reason has to travel with the absence: a
         * reason invented at the point of use would tell a reader the matrix was at fault
         * when the truth is that nothing could be read off the connection.
         *
         * A rule still branches only on the VERSION. The source is not a fact about the
         * statement and never a reason to judge it differently — a pin and a live read of
         * the same version must produce the same verdict, which is the whole point of the
         * pin. That property is pinned by a test rather than by hiding the field, because
         * hiding it would only have stopped the rules that exist today.
         */
        public ?ResolvedServerVersion $serverVersion = null,
        /**
         * The ordered column list THIS statement names — an index's key columns, a foreign
         * key's referencing columns — or an empty list when it names none.
         *
         * The same fact {@see MigrationStatementDigest::$keyColumns} carries for ANOTHER statement,
         * carried here for the statement being judged. It had to travel both ways: a rule that
         * compares its own key against the migration's indexes needs one of each, and reading
         * its own out of the canonical string — the only alternative before this field existed —
         * would put grammar back into a rule, which is what this whole projection prevents.
         *
         * ORDER is load-bearing, which is why it is a list and not a set: index coverage is a
         * LEFT PREFIX, so `(a, b)` answers a lookup on `(a)` and answers nothing for `(b)`.
         *
         * @var list<string>
         */
        public array $keyColumns = [],
        /**
         * Where this statement came from — migration, not a migration, or unknown.
         *
         * Already DECIDED by the time a rule sees it: the run resolved the registered migration
         * paths once and the subject applied them, so a rule reads an answer instead of computing
         * one. That matters beyond tidiness — a rule computing it would need the paths, would take
         * a shortcut to `database/migrations`, and would then miss a package path, a tenant
         * subdirectory, and call a seeder named like a migration a migration.
         *
         * Defaults to Unknown rather than to Migration, because the default is what a subject
         * built without provenance gets — a hand-constructed one in a test, a catalog row, a
         * snippet on the fast path — and a path-bound rule must answer `undetermined` there. The
         * opposite default would fire a Critical on every one of them.
         */
        public OriginBinding $originBinding = OriginBinding::Unknown,
        /**
         * Where this statement's VALUES came from — the file, or a binding at the call site.
         *
         * Needed because the two are indistinguishable by the time a rule sees them: `PASSWORD ?`
         * with a binding and `PASSWORD 'hunter2'` typed into the migration arrive as the same
         * canonical text. A secrets rule reading only the text necessarily reports the shape it
         * recommends.
         *
         * Defaults to Undeterminable for the same reason the origin binding defaults to Unknown: a
         * subject built without a capture behind it has no answer, and the confident default would
         * be the one that fires.
         */
        public ValueOrigin $valueOrigin = ValueOrigin::Undeterminable,
    ) {}

    /**
     * Whether the transaction context could not be resolved — the case a lock-hygiene rule
     * must report as undetermined rather than pass over.
     */
    public function transactionContextUnknown(): bool
    {
        return $this->transactionMode === TransactionMode::Undetermined;
    }

    /** Whether the statement was classified as the given kind — false when unclassified. */
    public function is(StatementKind $kind): bool
    {
        return $this->kind === $kind;
    }
}
