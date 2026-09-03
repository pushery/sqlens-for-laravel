<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TransactionMode;
use Pushery\SQLens\Capture\ValueOrigin;
use Pushery\SQLens\Contracts\Subject;
use Pushery\SQLens\Security\OriginBinding;

/**
 * The subject for captured migration SQL — the input of the whole lint suite and
 * the fast path.
 *
 * The rule contract is the CANONICALIZED statement, not Laravel's raw grammar
 * output: rules never regex on grammar quirks, so the raw text is deliberately
 * not offered as a convenient primary accessor. (The canonicalization itself is
 * a separate layer; this VO only holds the slot.)
 *
 * The capture mode is required so a pretend run can never be mistaken for truth.
 */
final readonly class MigrationSql implements Subject
{
    public function __construct(
        public string $canonicalStatement,
        public string $migrationClass,
        public string $sourceFile,
        public int $statementIndex,
        public MigrationDirection $direction,
        public bool $withinTransaction,
        public CaptureMode $mode,
        private SubjectContext $context,
        /**
         * The real class of the migration instance the captor loaded, when it loaded
         * one — the carrier of the class-level `#[SqlensIgnore]` attribute.
         *
         * It is NOT `migrationClass`: that is the migration NAME (the file basename the
         * repository records and a report prints), and Laravel's anonymous migrations
         * have no class of that name, so reflecting it would find nothing and the
         * annotation would be a silent no-op. Null when no instance was loaded — a
         * migration the pre-scan refused to load has no class to read an attribute off,
         * which is honest rather than a guess at one.
         */
        public ?string $annotationClass = null,
        /**
         * The canonical classification of this statement — what it does and what it
         * acts on — or null when the driver could not classify it. Null reaches a rule
         * as "unclassified", never as a guessed kind.
         */
        public ?StatementKind $statementKind = null,
        /** @var list<StatementTarget> the classified targets, empty when unclassified */
        public array $targets = [],
        /**
         * What the whole migration does, so a rule can judge this statement in the
         * light of its neighbors. Null on a subject built outside a capture (a test
         * double, the annotation carrier) — treated as an empty migration.
         */
        public ?MigrationContext $migration = null,
        /**
         * The resolved transaction mode, or null when the statement never reached
         * canonicalization. Carried alongside `$withinTransaction` rather than replacing it:
         * the boolean is the migrator's own flag, this is what the resolver made of it, and a
         * rule that must not go silent on an unknown context needs to tell the two apart.
         */
        public ?TransactionMode $transactionMode = null,
        /**
         * The ordered column list the classifier read off this statement, empty when it
         * names none. Carried on the subject purely to reach {@see canonicalView()}: the
         * migration's OTHER statements already offer theirs through the digest stream, and a
         * rule comparing its own key against them would otherwise have to re-read the
         * canonical SQL to get one of the two sides.
         *
         * @var list<string>
         */
        public array $keyColumns = [],
        /**
         * Where this statement's values came from, decided by the capture layer from the bindings
         * it already held. Undeterminable when nothing captured this — a synthetic subject, a
         * catalog row — which is what a secrets rule must read as "no answer available".
         */
        public ValueOrigin $valueOrigin = ValueOrigin::Undeterminable,
    ) {}

    /**
     * The rule-facing projection: the canonical facts a rule may reason about, and
     * nothing else. Rules receive this rather than the subject so they cannot reach
     * the raw SQL or the provenance — see {@see MigrationStatementView}.
     */
    public function canonicalView(): MigrationStatementView
    {
        return new MigrationStatementView(
            $this->canonicalStatement,
            $this->statementKind,
            $this->targets,
            $this->migration ?? MigrationContext::empty(),
            $this->statementIndex,
            $this->withinTransaction,
            $this->transactionMode,
            // The run's version resolution, taken from the context rather than stored a
            // second time on the subject: the context is where the run put it, and a
            // second copy is a second thing to keep in step.
            $this->context->resolvedServerVersion,
            $this->keyColumns,
            // Decided HERE, once, from the run's own resolved paths — so every rule reads the same
            // answer and none of them has to know what a migration path looks like. A run that
            // never established them (a catalog subject, a synthetic one) yields Unknown, which is
            // what a path-bound rule reports as undetermined rather than passing over.
            $this->context->pathBinding?->for($this->sourceFile) ?? OriginBinding::Unknown,
            $this->valueOrigin,
        );
    }

    public function kind(): SubjectKind
    {
        return SubjectKind::MigrationSql;
    }

    public function identity(): string
    {
        return sprintf(
            '%s:%s:%d',
            $this->migrationClass,
            $this->direction->value,
            $this->statementIndex,
        );
    }

    public function context(): SubjectContext
    {
        return $this->context;
    }

    /**
     * Whether this statement actually runs inside a transaction. Derived from
     * Laravel's migration property — the basis for the later Squawk transaction
     * assumption mapping.
     */
    public function runsInTransaction(): bool
    {
        return $this->withinTransaction;
    }
}
