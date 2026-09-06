<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Canonical;

use Pushery\SQLens\Canonical\Classification\SignatureElement;
use Pushery\SQLens\Canonical\Classification\StatementClassificationProfile;
use Pushery\SQLens\Canonical\Classification\StatementSignature;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\TargetRole;
use Pushery\SQLens\Canonical\TransactionMarkers;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * PostgreSQL's canonicalization quirks — a thin shell over the data the generic
 * normalization stages read. Nothing here imports the MySQL namespace; the two
 * drivers never know about each other.
 */
final class PgsqlCanonicalization implements DriverCanonicalization
{
    public function quotingCharacter(): string
    {
        return '"';
    }

    public function foldsUnquotedIdentifiersToLowerCase(): bool
    {
        return true;
    }

    /** @return list<string> */
    public function keywords(): array
    {
        return [
            // Structural keywords — the shape of the statement.
            'ADD', 'ALTER', 'AS', 'CASCADE', 'CHECK', 'COLUMN', 'CONCURRENTLY', 'CONSTRAINT',
            'CREATE', 'DEFAULT', 'DELETE', 'DROP', 'EXISTS', 'FOREIGN', 'FROM', 'IF', 'IN', 'INDEX',
            'INSERT', 'INTO', 'KEY', 'NOT', 'NULL', 'ON', 'ONLY', 'PRIMARY', 'REFERENCES', 'RENAME',
            'SCHEMA', 'SELECT', 'SET', 'TABLE', 'TO', 'TRUNCATE', 'TYPE', 'UNIQUE', 'UPDATE', 'USING', 'VALID',
            'VALIDATE', 'VALUES', 'WHERE',

            // The referential actions and the collation clause. `CASCADE` was already here, its
            // three siblings were not — so `ON DELETE CASCADE` folded while `ON DELETE RESTRICT`
            // did not, which is one statement shape canonicalizing two ways depending on which
            // action a migration happens to use.
            'ACTION', 'COLLATE', 'NO', 'RESTRICT',

            // The QUERY vocabulary — the same hole as on MySQL, and for the same reason: the
            // keyword guard's corpus is generated from the SCHEMA builder, so no data statement
            // ever reached it. `where "id" between 1 and 1000` folded neither word, so a builder
            // statement and the identical hand-written one produced two canonical forms and two
            // fingerprints.
            'AND', 'ASC', 'BETWEEN', 'BY', 'DESC', 'INNER', 'JOIN', 'LEFT', 'LIMIT', 'OFFSET',
            'OR', 'ORDER', 'RIGHT',

            // Found by the corpus guard rather than by a rule tripping over them: `bigserial` is
            // what `$table->id()` emits, `identity` rides in every `->change()`, and a column
            // comment is a whole statement shape that folded nothing at all.
            'BIGSERIAL', 'COMMENT', 'IDENTITY', 'IS',

            // TYPE names and the words that ride with them. Without these, `varchar(100)` and
            // `VARCHAR(100)` canonicalize differently — ONE statement, TWO fingerprints — and a
            // baseline entry stops matching the moment someone reformats a migration. Measured from
            // what Laravel's PostgreSQL grammar actually emits, not recalled.
            //
            // Safe by construction: this stage runs AFTER identifier normalization, so a column
            // named `text` is already quoted and a BARE word is unambiguously the keyword.
            'BIGINT', 'BOOLEAN', 'BYTEA', 'CHAR', 'DATE', 'DECIMAL', 'DOUBLE', 'FLOAT', 'GEOGRAPHY',
            'GEOMETRY', 'INET', 'INTEGER', 'JSON', 'JSONB', 'MACADDR', 'PRECISION', 'REAL',
            'SMALLINT', 'TEXT', 'TIME', 'TIMESTAMP', 'TSVECTOR', 'UUID', 'VARCHAR', 'VECTOR',
            'WITH', 'WITHOUT', 'ZONE',

            // The PRIVILEGE vocabulary, and `GRANT`/`REVOKE` are the two that had to be here for
            // the statement to be canonicalizable at all — not merely to fold nicely.
            //
            // The classifier's fallback refuses a statement whose LEAD token is not a keyword, and
            // a word absent from this list tokenizes as an identifier. So `GRANT SELECT ON orders
            // TO PUBLIC` came back `unrecognized_statement_form`, the capture layer built no
            // subject for it, and every migration-security rule over a grant was unreachable in a
            // real run while green in every test it had. Two lists had to agree and only one was
            // edited; this comment sits on the half that is easy to forget.
            //
            // The rest of the vocabulary rides along for determinism rather than reachability:
            // without them `GRANT ALL PRIVILEGES` and `grant all privileges` canonicalize to two
            // different strings, which is two fingerprints for one statement and a baseline entry
            // that stops matching when somebody reformats a migration.
            //
            // The list is DELIBERATELY short of `PUBLIC`, and that is measured rather than cautious:
            // adding it turned `SELECT * FROM public.users` into `SELECT * FROM "public".users`,
            // because `public` is PostgreSQL's default schema and appears in ordinary identifiers
            // everywhere. A grant needs only its LEAD token to be a keyword, so PUBLIC buys nothing
            // and costs the whole schema vocabulary. `FUNCTION`, `LANGUAGE` and `SECURITY` are out
            // for the same reason: each one moved a canonical form that a characterization test
            // had pinned, and none of them is needed for a statement to be recognized.
            'GRANT', 'REVOKE', 'PRIVILEGES', 'OPTION', 'USAGE', 'ALL',
        ];
    }

    /** @return list<string> */
    public function stringLiteralDelimiters(): array
    {
        return ["'"];
    }

    /** @return list<string> */
    public function commentSyntaxes(): array
    {
        return ['--', '/*'];
    }

    public function supportsDdlTransactions(): bool
    {
        return true;
    }

    public function supportsDollarQuotedStrings(): bool
    {
        return true;
    }

    public function supportsDelimiterRedefinition(): bool
    {
        return false;
    }

    public function usesBackslashStringEscapes(): bool
    {
        return false;
    }

    /**
     * `psql` reads a line that starts with a backslash itself — `\i other.sql`,
     * `\set ON_ERROR_STOP on` — and the server never receives it. Declared here
     * so the splitter can end such a line at the newline instead of hunting for
     * a semicolon it will not find.
     */
    public function clientDirectivePrefix(): string
    {
        return '\\';
    }

    /** @return list<CanonicalizationStage> */
    public function stages(): array
    {
        return [];
    }

    public function transactionMarkers(): TransactionMarkers
    {
        return new TransactionMarkers(
            openers: ['BEGIN', 'START'],
            closers: ['COMMIT', 'ROLLBACK', 'END'],
        );
    }

    public function statementClassification(): StatementClassificationProfile
    {
        $table = SchemaObjectType::Table;
        $index = SchemaObjectType::Index;
        $constraint = SchemaObjectType::Constraint;
        $column = SchemaObjectType::Column;
        $schema = SchemaObjectType::Schema;

        return new StatementClassificationProfile(
            signatures: [
                // CREATE [UNIQUE] INDEX [CONCURRENTLY] <i> ON <t> (<c>, …) — and NOTHING after it.
                //
                // Tried BEFORE the column-less variant below, which stays as the fallback: a shape
                // whose list cannot be read still classifies as an index rather than falling
                // through to unknown, it simply carries no columns. Degrading to "no columns" is
                // safe for every reader — a rule asking about coverage sees nothing it can conclude
                // from and says nothing.
                //
                // The signature ENDS at the closing parenthesis, which is what keeps the plain
                // b-tree index apart from every qualified form that reads exactly like it: a
                // PARTIAL index (`… (a) WHERE …`) and one carrying an INCLUDE payload both have a
                // plain leading list, and a partial index covers no foreign-key lookup at all —
                // the catalog reading excludes it by predicate, so this reading has to exclude it
                // too, or the two halves of a rule disagree about what "covered" means. An index
                // named with an explicit method (`… USING gin (…)`) never reaches the list: USING
                // is a keyword, so the run finds no identifier and this signature declines.
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('CREATE'), SignatureElement::optionalModifiers(),
                    SignatureElement::keyword('INDEX'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($index),
                    SignatureElement::keyword('ON'), SignatureElement::target($table),
                    SignatureElement::columnList(), SignatureElement::endOfStatement(),
                ]),
                // CREATE [UNIQUE] INDEX [CONCURRENTLY] <i> ON <t>
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('CREATE'), SignatureElement::optionalModifiers(),
                    SignatureElement::keyword('INDEX'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($index),
                    SignatureElement::keyword('ON'), SignatureElement::target($table),
                ]),
                // CREATE TABLE [IF NOT EXISTS] <t>
                new StatementSignature(StatementKind::CreateTable, [
                    SignatureElement::keyword('CREATE'), SignatureElement::optionalModifiers(),
                    SignatureElement::keyword('TABLE'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($table),
                ]),
                // DROP INDEX [CONCURRENTLY] [IF EXISTS] <i>
                new StatementSignature(StatementKind::DropIndex, [
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('INDEX'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($index),
                ]),
                // DROP TABLE [IF EXISTS] <t>
                new StatementSignature(StatementKind::DropTable, [
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                ]),
                // DROP SCHEMA [IF EXISTS] <s> [CASCADE | RESTRICT]
                //
                // Above the DROP TABLE arm only for readability — the two cannot collide, because
                // the second keyword decides. CASCADE and RESTRICT are trailing tokens and are not
                // matched here; the RULE reads them off the canonical SQL, because they change what
                // the statement reaches rather than what it targets.
                new StatementSignature(StatementKind::DropSchema, [
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('SCHEMA'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($schema),
                ]),
                // TRUNCATE TABLE <t>  /  TRUNCATE <t>
                new StatementSignature(StatementKind::TruncateTable, [
                    SignatureElement::keyword('TRUNCATE'), SignatureElement::keyword('TABLE'),
                    SignatureElement::target($table),
                ]),
                new StatementSignature(StatementKind::TruncateTable, [
                    SignatureElement::keyword('TRUNCATE'), SignatureElement::target($table),
                ]),
                // ALTER TABLE [ONLY] <t> ADD CONSTRAINT <k> FOREIGN KEY (<c>, …) REFERENCES <t2>
                //
                // The REFERENCING columns, which is the side a coverage question is about. The
                // keyword REFERENCES ends the run, so the referenced table's own column list is
                // never swept in — two lists on one statement would be indistinguishable
                // afterwards, and the wrong one would answer the question.
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::seekKeyword('KEY'), SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE [ONLY] <t> ADD CONSTRAINT <k> … REFERENCES <t2>
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ---------------------------------------------------------------------------
                // The two constraints PostgreSQL IMPLEMENTS WITH AN INDEX, with their columns.
                //
                // `ADD CONSTRAINT <k> UNIQUE (…)` and `ADD [CONSTRAINT <k>] PRIMARY KEY (…)` each
                // build a b-tree index over exactly the columns they name — which is why the
                // columns have to travel. Without them the everyday pivot table reads as
                // unindexed: `$table->unique(['team_id', 'user_id'])` is the framework's own
                // idiom, it covers the foreign key on `team_id`, and a coverage rule that could
                // not see it reported the correct migration and then recommended an index the
                // audit suite calls redundant. The KIND is unchanged from what these shapes
                // already classified as (a named constraint is `AddConstraint`, a bare
                // `ADD PRIMARY KEY` is `AlterTable`), so nothing that dispatches on kind moves.
                //
                // Only the plain form is read: `UNIQUE NULLS NOT DISTINCT (…)` and a deferrable
                // or `USING INDEX` variant carry words between the keyword and the list, so the
                // list element declines and the statement falls through to the bare form below,
                // carrying no columns.
                // ---------------------------------------------------------------------------
                // ALTER TABLE [ONLY] <t> ADD CONSTRAINT <k> UNIQUE (<c>, …)
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::columnList(),
                ]),
                // ALTER TABLE [ONLY] <t> ADD CONSTRAINT <k> PRIMARY KEY (<c>, …)
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::keyword('PRIMARY'), SignatureElement::keyword('KEY'),
                    SignatureElement::columnList(),
                ]),
                // ALTER TABLE [ONLY] <t> ADD CONSTRAINT <k>
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                ]),
                // ALTER TABLE [ONLY] <t> VALIDATE CONSTRAINT <k>
                //
                // The KIND stays `AlterTable`, exactly as the UNIQUE/PRIMARY KEY shapes above keep
                // theirs: nothing that dispatches on kind moves, and a statement that was
                // `alter_table` yesterday is still `alter_table` today. What this signature adds is
                // the CONSTRAINT it names, which the bare fallback drops -- and without that name a
                // reader of the pending set can see that some constraint is being validated but not
                // which one.
                //
                // It is the one shape that yields `alter_table` WITH a constraint target: `ADD` and
                // `DROP CONSTRAINT` each carry their own kind. A later signature that broke that
                // would need to say so here.
                new StatementSignature(StatementKind::AlterTable, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('VALIDATE'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                ]),
                // ALTER TABLE [ONLY] <t> DROP CONSTRAINT [IF EXISTS] <k>
                new StatementSignature(StatementKind::DropConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($constraint),
                ]),
                // ALTER TABLE [ONLY] <t> ADD COLUMN [IF NOT EXISTS] <c>
                //
                // Mirrors the DROP COLUMN signature below it, and closes an asymmetry rather than
                // opening one: MySQL's grammar has named this statement `AddColumn` since it
                // shipped, while PostgreSQL let it fall through to the bare `AlterTable` fallback —
                // so the two engines disagreed about what the same statement IS, and every reader
                // keyed on the kind inherited that disagreement.
                //
                // ⚠️ Converging the two makes PostgreSQL stop producing `AlterTable` here, which
                // takes the statement away from every reader that names only that kind. Each of the
                // nine was checked before this landed: three needed `AddColumn` added (two of them
                // were ALREADY blind on MySQL, which is how the defect surfaced), and six are inert
                // because their own text match — `ALTER COLUMN … TYPE`, `ALTER COLUMN … SET NOT
                // NULL`, `ADD (CONSTRAINT|PRIMARY KEY|UNIQUE)`, or a scan for constraint targets —
                // cannot match an `ADD COLUMN` under either kind.
                new StatementSignature(StatementKind::AddColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                ]),
                // ALTER TABLE [ONLY] <t> DROP COLUMN [IF EXISTS] <c>
                new StatementSignature(StatementKind::DropColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                ]),
                // ALTER TABLE [ONLY] <t> RENAME …
                new StatementSignature(StatementKind::Rename, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('RENAME'),
                ]),
                // ALTER TABLE [ONLY] <t> ADD PRIMARY KEY (<c>, …)  /  ADD UNIQUE (<c>, …)
                //
                // The UNNAMED forms of the two index-backed constraints — `$table->primary([…])`
                // compiles to the first of them, with no CONSTRAINT keyword anywhere, which is
                // why it never matched a constraint signature and why the 1:1 and pivot shapes
                // read as unindexed. The kind stays `AlterTable`, the one they already carried.
                new StatementSignature(StatementKind::AlterTable, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('PRIMARY'),
                    SignatureElement::keyword('KEY'), SignatureElement::columnList(),
                ]),
                new StatementSignature(StatementKind::AlterTable, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('UNIQUE'),
                    SignatureElement::columnList(),
                ]),
                // ALTER TABLE [ONLY] <t> … (any other alter)
                new StatementSignature(StatementKind::AlterTable, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                ]),
                // INSERT INTO <t> …
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('INSERT'), SignatureElement::keyword('INTO'),
                    SignatureElement::target($table),
                ]),
                // UPDATE <t> SET <c> = …, <c> = … — the assignment targets, in order.
                //
                // BEFORE the plain `UPDATE <t>` signature below, because signatures are tried in
                // order and the plain one matches everything this one does. It captures the columns
                // the statement WRITES, which is what a debt rule asking "was this new column
                // back-filled" needs; the columns it reads sit inside expressions and stay there.
                //
                // A clause this element cannot read whole — `SET a = (SELECT …), b = 2` — declines
                // and falls through to the plain signature, so the statement still classifies as
                // `Dml` and simply carries no columns. Every reader turns that into "I cannot
                // conclude", never into a wrong conclusion.
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('UPDATE'), SignatureElement::target($table),
                    SignatureElement::keyword('SET'),
                    // PostgreSQL ends an UPDATE's SET clause with one of these three.
                    SignatureElement::backfillTargets(['FROM', 'WHERE', 'RETURNING']),
                ]),
                // UPDATE <t> …
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('UPDATE'), SignatureElement::target($table),
                ]),
                // DELETE FROM <t> …
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('DELETE'), SignatureElement::keyword('FROM'),
                    SignatureElement::target($table),
                ]),
            ],
            modifiers: ['UNIQUE', 'CONCURRENTLY', 'IF', 'NOT', 'EXISTS', 'ONLY'],
            leadFallback: [
                'CREATE' => StatementKind::DdlOther,
                'ALTER' => StatementKind::DdlOther,
                'DROP' => StatementKind::DdlOther,
                'TRUNCATE' => StatementKind::DdlOther,
                'INSERT' => StatementKind::Dml,
                'UPDATE' => StatementKind::Dml,
                'DELETE' => StatementKind::Dml,
                'SELECT' => StatementKind::Unknown,
                // A session config command (SET lock_timeout, SET LOCAL statement_timeout).
                // It must be recognized, not refused — a migration that sets its own timeouts is
                // doing the right thing, and reporting it undetermined would refuse to lint the
                // very migrations the lock-hygiene rules ask for. It carries its OWN kind rather
                // than Unknown, because "recognized, changes nothing" and "not recognized, could
                // be anything" are opposite answers to a rule that must hedge over what it could
                // not read.
                'SET' => StatementKind::SessionSetting,

                // The privilege grammar. Measured, and the measurement is the reason these two
                // lines exist: without them `GRANT SELECT ON orders TO PUBLIC` was
                // UNRECOGNIZED_STATEMENT_FORM, so the capture layer never built a subject for it —
                // and every migration-security rule that judges a GRANT could not fire at all. Not
                // rarely. At all. The rules passed their own tests, which construct a subject
                // directly, and the whole family was silent in production.
                //
                // `DdlOther` rather than a kind of its own, and that is the consistent answer
                // rather than the convenient one: `ALTER DEFAULT PRIVILEGES … GRANT … TO …` already
                // classified as `DdlOther` through its `ALTER` lead. One privilege operation
                // written two ways would otherwise carry two kinds, and a rule dispatching on kind
                // would see half of it.
                //
                // REVOKE rides along for the same reason SET did: it is the other half of the same
                // grammar, it appears in the down() leg of every migration that grants, and leaving
                // it out would make a reversible migration uncheckable in one direction.
                'GRANT' => StatementKind::DdlOther,
                'REVOKE' => StatementKind::DdlOther,

                // `COMMENT ON COLUMN`/`COMMENT ON TABLE`, and it is not an exotic form: Laravel
                // appends one to EVERY `->change()`. `compileComment()` fires on
                // `! is_null($column->comment) || $column->change`, so a plain
                // `$table->string('endpoint', 1024)->change()` emits `comment on column … is NULL`
                // beside its `alter table`. One unrecognized statement makes the whole migration
                // report CAP.L0.UNDETERMINED_CAPTURE, so this word decided whether a `->change()`
                // migration was checked at all — and `->change()` is the Laravel spelling for the
                // column rewrites and NOT NULL sets the lock-hygiene rules exist for. Measured in a
                // consumer over 56 files: 3 used `->change()`, 3 were uncanonicalizable, and the
                // intersection was 3 of 3.
                //
                // It is the hole the note on the MySQL twin's keyword list warns about — "two lists
                // have to agree for a statement form to work" — and here only the first was ever
                // edited. `COMMENT` and `IS` sit in the keyword list above under a note calling a
                // column comment "a whole statement shape that folded nothing at all"; that fixed
                // the FOLDING, so two spellings stopped producing two fingerprints, and left the
                // statement just as unrecognized. Folding a word and classifying a form are two
                // lists, and a fix to one reads exactly like a fix to both.
                //
                // `DdlOther` for the same reason GRANT takes it, and here the case is easier: a
                // comment writes a catalog description, changes no schema and no row, and takes
                // only a ShareUpdateExclusive lock — so no safety rule has anything to say about
                // it. Reaching it through the fallback rather than a signature also keeps its
                // target set empty, which is the honest shape: the statement that changed the
                // column is the `alter table` beside it, and that one carries the target.
                'COMMENT' => StatementKind::DdlOther,
            ],
        );
    }
}
