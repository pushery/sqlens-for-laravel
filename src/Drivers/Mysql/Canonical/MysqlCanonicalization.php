<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Canonical;

use Pushery\SQLens\Canonical\Classification\SignatureElement;
use Pushery\SQLens\Canonical\Classification\StatementClassificationProfile;
use Pushery\SQLens\Canonical\Classification\StatementSignature;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\TargetRole;
use Pushery\SQLens\Canonical\TransactionMarkers;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DeclaresReservedWords;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * MySQL's canonicalization quirks — a thin shell over the data the generic
 * normalization stages read. Nothing here imports the PostgreSQL namespace; the
 * two drivers never know about each other.
 */
final class MysqlCanonicalization implements DeclaresReservedWords, DriverCanonicalization
{
    public function quotingCharacter(): string
    {
        return '`';
    }

    public function foldsUnquotedIdentifiersToLowerCase(): bool
    {
        // MySQL keeps identifiers as written (case-sensitivity is platform- and
        // lower_case_table_names-dependent), so canonicalization does not fold.
        return false;
    }

    /**
     * The words of {@see keywords()} that MySQL accepts as an unquoted table, column, index or
     * constraint name, upper case.
     *
     * Read from the server rather than from memory: `information_schema.KEYWORDS` on MySQL 8.4 marks
     * each keyword reserved or not, and a name may be any word it does not reserve. Three words of the
     * list are no keyword to the server at all.
     *
     * @var list<string>
     */
    private const array UNRESERVED_NAMES = [
        // information_schema.KEYWORDS, RESERVED = 0.
        'ACTION', 'AFTER', 'ALGORITHM', 'ALWAYS', 'AUTO_INCREMENT', 'DATE', 'DATETIME', 'ENGINE', 'ENUM',
        'FIRST', 'GEOMETRY', 'IDENTIFIED', 'JSON', 'MODIFY', 'NO', 'OFFSET', 'PASSWORD', 'PRIVILEGES',
        'TEXT', 'TIME', 'TIMESTAMP', 'TRUNCATE', 'USER', 'YEAR',
        // No keyword to the server.
        'INPLACE', 'INSTANT', 'VECTOR',
    ];

    /**
     * The keywords that END a column's type and begin its modifiers.
     *
     * MySQL's list, and it cannot be PostgreSQL's. `CHARACTER` is here because `CHARACTER SET
     * utf8mb4` is a per-column MODIFIER on this engine; on PostgreSQL the same word opens the type
     * `CHARACTER VARYING`, so a shared list would truncate one engine's types or swallow the
     * other's modifiers. That pair is the reason this list belongs to the driver.
     *
     * `UNSIGNED` and `ZEROFILL` stay OUT on purpose: they are part of what the type IS, and the
     * shared normalizer reads `unsigned` off the raw text to set its own flag. Terminating there
     * would drop the distinction the flag exists for.
     *
     * @var list<string>
     */
    private const array COLUMN_TYPE_TERMINATORS = [
        'NOT', 'NULL', 'DEFAULT', 'PRIMARY', 'UNIQUE', 'REFERENCES', 'CHECK', 'CONSTRAINT',
        'COLLATE', 'COMMENT', 'GENERATED', 'AUTO_INCREMENT', 'CHARACTER', 'KEY', 'INVISIBLE',
        'STORAGE', 'AS',
    ];

    /**
     * The words MySQL refuses as an unquoted table, column, index or constraint name, upper case.
     *
     * Read from the server rather than from memory: the words `information_schema.KEYWORDS` marks
     * `RESERVED` on MySQL 8.4. A name from this list is quoted in the canonical form, so that it
     * parses where a suggestion writes it. `GROUPS` is one of them since MySQL 8.0, which makes a
     * table Laravel would call `groups` the case most likely to meet it.
     *
     * @var list<string>
     */
    private const array RESERVED_WORDS = [
        'ACCESSIBLE', 'ADD', 'ALL', 'ALTER', 'ANALYZE', 'AND', 'AS', 'ASC', 'ASENSITIVE', 'BEFORE',
        'BETWEEN', 'BIGINT', 'BINARY', 'BLOB', 'BOTH', 'BY', 'CALL', 'CASCADE', 'CASE', 'CHANGE',
        'CHAR', 'CHARACTER', 'CHECK', 'COLLATE', 'COLUMN', 'CONDITION', 'CONSTRAINT', 'CONTINUE',
        'CONVERT', 'CREATE', 'CROSS', 'CUBE', 'CUME_DIST', 'CURRENT_DATE', 'CURRENT_TIME', 'CURRENT_TIMESTAMP',
        'CURRENT_USER', 'CURSOR', 'DATABASE', 'DATABASES', 'DAY_HOUR', 'DAY_MICROSECOND', 'DAY_MINUTE',
        'DAY_SECOND', 'DEC', 'DECIMAL', 'DECLARE', 'DEFAULT', 'DELAYED', 'DELETE', 'DENSE_RANK',
        'DESC', 'DESCRIBE', 'DETERMINISTIC', 'DISTINCT', 'DISTINCTROW', 'DIV', 'DOUBLE', 'DROP',
        'DUAL', 'EACH', 'ELSE', 'ELSEIF', 'EMPTY', 'ENCLOSED', 'ESCAPED', 'EXCEPT', 'EXISTS', 'EXIT',
        'EXPLAIN', 'FALSE', 'FETCH', 'FIRST_VALUE', 'FLOAT', 'FLOAT4', 'FLOAT8', 'FOR', 'FORCE',
        'FOREIGN', 'FROM', 'FULLTEXT', 'FUNCTION', 'GENERATED', 'GET', 'GRANT', 'GROUP', 'GROUPING',
        'GROUPS', 'HAVING', 'HIGH_PRIORITY', 'HOUR_MICROSECOND', 'HOUR_MINUTE', 'HOUR_SECOND', 'IF',
        'IGNORE', 'IN', 'INDEX', 'INFILE', 'INNER', 'INOUT', 'INSENSITIVE', 'INSERT', 'INT', 'INT1',
        'INT2', 'INT3', 'INT4', 'INT8', 'INTEGER', 'INTERSECT', 'INTERVAL', 'INTO', 'IO_AFTER_GTIDS',
        'IO_BEFORE_GTIDS', 'IS', 'ITERATE', 'JOIN', 'JSON_TABLE', 'KEY', 'KEYS', 'KILL', 'LAG',
        'LAST_VALUE', 'LATERAL', 'LEAD', 'LEADING', 'LEAVE', 'LEFT', 'LIKE', 'LIMIT', 'LINEAR',
        'LINES', 'LOAD', 'LOCALTIME', 'LOCALTIMESTAMP', 'LOCK', 'LONG', 'LONGBLOB', 'LONGTEXT', 'LOOP',
        'LOW_PRIORITY', 'MATCH', 'MAXVALUE', 'MEDIUMBLOB', 'MEDIUMINT', 'MEDIUMTEXT', 'MIDDLEINT',
        'MINUTE_MICROSECOND', 'MINUTE_SECOND', 'MOD', 'MODIFIES', 'NATURAL', 'NO_WRITE_TO_BINLOG',
        'NOT', 'NTH_VALUE', 'NTILE', 'NULL', 'NUMERIC', 'OF', 'ON', 'OPTIMIZE', 'OPTIMIZER_COSTS',
        'OPTION', 'OPTIONALLY', 'OR', 'ORDER', 'OUT', 'OUTER', 'OUTFILE', 'OVER', 'PARTITION',
        'PERCENT_RANK', 'PRECISION', 'PRIMARY', 'PROCEDURE', 'PURGE', 'QUALIFY', 'RANGE', 'RANK', 'READ',
        'READ_WRITE', 'READS', 'REAL', 'RECURSIVE', 'REFERENCES', 'REGEXP', 'RELEASE', 'RENAME',
        'REPEAT', 'REPLACE', 'REQUIRE', 'RESIGNAL', 'RESTRICT', 'RETURN', 'REVOKE', 'RIGHT', 'RLIKE',
        'ROW', 'ROW_NUMBER', 'ROWS', 'SCHEMA', 'SCHEMAS', 'SECOND_MICROSECOND', 'SELECT', 'SENSITIVE',
        'SEPARATOR', 'SET', 'SHOW', 'SIGNAL', 'SMALLINT', 'SPATIAL', 'SPECIFIC', 'SQL',
        'SQL_BIG_RESULT', 'SQL_CALC_FOUND_ROWS', 'SQL_SMALL_RESULT', 'SQLEXCEPTION', 'SQLSTATE',
        'SQLWARNING', 'SSL', 'STARTING', 'STORED', 'STRAIGHT_JOIN', 'SYSTEM', 'TABLE', 'TABLESAMPLE', 'TERMINATED',
        'THEN', 'TINYBLOB', 'TINYINT', 'TINYTEXT', 'TO', 'TRAILING', 'TRIGGER', 'TRUE', 'UNDO',
        'UNION', 'UNIQUE', 'UNLOCK', 'UNSIGNED', 'UPDATE', 'USAGE', 'USE', 'USING', 'UTC_DATE',
        'UTC_TIME', 'UTC_TIMESTAMP', 'VALUES', 'VARBINARY', 'VARCHAR', 'VARCHARACTER', 'VARYING',
        'VIRTUAL', 'WHEN', 'WHERE', 'WHILE', 'WINDOW', 'WITH', 'WRITE', 'XOR', 'YEAR_MONTH',
        'ZEROFILL',
    ];

    /** @return list<string> */
    public function reservedWords(): array
    {
        return self::RESERVED_WORDS;
    }

    /** @return list<string> */
    public function keywords(): array
    {
        return [
            // Structural keywords — the shape of the statement.
            'ADD', 'AFTER', 'ALGORITHM', 'ALTER', 'AS', 'CHANGE', 'CHECK', 'COLUMN', 'CONSTRAINT', 'CONVERT',
            'CREATE', 'DEFAULT', 'DELETE', 'DROP', 'ENGINE', 'EXISTS', 'FIRST', 'FOREIGN', 'FROM',
            'FULLTEXT', 'IF', 'INDEX', 'INPLACE', 'INSERT', 'INSTANT', 'INTO', 'KEY', 'LOCK',
            'MODIFY', 'NOT', 'NULL', 'ON', 'PRIMARY', 'REFERENCES', 'RENAME', 'SELECT', 'SPATIAL',
            'TABLE', 'TO', 'TRUNCATE', 'UNIQUE', 'UNSIGNED', 'UPDATE', 'VALUES', 'WHERE',

            // Column and table ATTRIBUTES, and the referential actions. Measured, like the types
            // below: the grammar emits `default character set … collate '…'`, `auto_increment`, and
            // `on delete cascade`, none of which folded before.
            //
            // `CHARACTER` is the one that mattered most, and not because it looked untidy: `SET`
            // was already here as a type name, so `character set` came out HALF folded — the shape
            // that reads as canonical while not being it, which is worse than leaving it alone.
            'ACTION', 'AUTO_INCREMENT', 'CASCADE', 'CHARACTER', 'COLLATE', 'NO', 'RESTRICT',

            // The QUERY vocabulary — the words a data statement is built from. They were missing
            // because the keyword guard's corpus is generated from the SCHEMA builder, so no DML
            // ever reached it: `where status = 'old' limit 1000` came out with `limit` unfolded,
            // and the identical statement written by hand as raw SQL came out with `LIMIT`. One
            // statement, two canonical forms, two fingerprints — the exact drift the folding
            // exists to prevent, on the statements a backfill rule has to read.
            'AND', 'ASC', 'BETWEEN', 'BY', 'DESC', 'IN', 'INNER', 'IS', 'JOIN', 'LEFT', 'LIMIT',
            'OFFSET', 'OR', 'ORDER', 'RIGHT',

            // The ACCOUNT vocabulary. `CREATE USER app IDENTIFIED BY '…'` is an ordinary line in a
            // migration that provisions its own runtime role, and none of its words folded: the
            // list carried `CREATE` and `BY` but never `USER`, `IDENTIFIED`, `WITH` or `PASSWORD`.
            //
            // That is a determinism hole before it is anything else. `Identified By` and
            // `IDENTIFIED BY` are the same statement and were canonicalizing to two different
            // forms, so one of them stopped matching its own baseline entry the moment somebody
            // reformatted the migration — the exact drift the folding exists to prevent.
            //
            // It is also what a rule about credentials reads. A rule matching the canonical text
            // for a password clause cannot see one that never folded, and the failure is the quiet
            // direction: no error, just a secret that goes unreported.
            //
            // `PASSWORD` is deliberately here even though MySQL 8.4 has retired
            // `IDENTIFIED BY PASSWORD '<hash>'`: a migration written years ago still says it, and
            // a hash in version control is a secret in version control.
            'IDENTIFIED', 'PASSWORD', 'USER', 'WITH',

            // TYPE names, and they belong here for the same reason the rest do: without them
            // `varchar(100)` and `VARCHAR(100)` canonicalize differently, so ONE statement gets TWO
            // fingerprints — and a baseline entry stops matching the moment someone reformats a
            // migration. The list is measured from what Laravel's MySQL grammar actually emits —
            // captured and pinned by a characterization test — rather than recalled from memory.
            //
            // Safe by construction: this stage runs AFTER identifier normalization, so a column
            // named `varchar` is already quoted and a BARE word is unambiguously the keyword.
            'BIGINT', 'BINARY', 'BLOB', 'CHAR', 'DATE', 'DATETIME', 'DECIMAL', 'DOUBLE', 'ENUM',
            'FLOAT', 'GEOMETRY', 'INT', 'JSON', 'LONGTEXT', 'MEDIUMINT', 'MEDIUMTEXT', 'SET',
            'SMALLINT', 'TEXT', 'TIME', 'TIMESTAMP', 'TINYINT', 'TINYTEXT', 'VARBINARY', 'VARCHAR',
            'VECTOR', 'YEAR',

            // The PRIVILEGE vocabulary. `GRANT` and `REVOKE` are here for REACHABILITY, not for
            // tidiness: the classifier's fallback refuses a statement whose lead token is not a
            // keyword, and a word missing from this list tokenizes as an identifier. Without them
            // a grant was `unrecognized_statement_form`, no subject was built, and every rule that
            // judges one was unreachable in a real run — on both engines, green in every test.
            //
            // Two lists have to agree for a statement form to work: this one and `leadFallback`
            // below. Only one of them was edited when this was found, which is exactly how the
            // hole survived; the note sits on both halves now.
            //
            // The rest ride along for determinism — `GRANT ALL PRIVILEGES` and its lower-case twin
            // must canonicalize to one string, or one statement carries two fingerprints. The list
            // stops where measurement said to: the routine and view vocabulary each moved a form
            // that a characterization test had pinned, and none of it is needed for recognition.
            // (Named indirectly on purpose — a tripwire in the schema-builder suite watches this
            // file for the view keyword, and a comment explaining why it is absent would fire it.)
            'GRANT', 'REVOKE', 'PRIVILEGES', 'OPTION', 'ALL',

            // The GENERATED-column vocabulary, and it slipped through for the reason this file has
            // already recorded twice: the keyword guard's corpus is generated from the SCHEMA
            // builder, and `GENERATED ALWAYS AS IDENTITY` is written by hand or through `->change()`
            // rather than by the builder's ordinary path. So no corpus statement ever carried these
            // words, and `generated always as identity` folded only its `AS` — one statement, two
            // canonical forms, two fingerprints, and a baseline entry that stops matching when
            // somebody reformats a migration.
            //
            // Measured before and after rather than reasoned: with these absent, the same DDL in two
            // casings produced two different canonical strings.
            'ALWAYS', 'GENERATED', 'STORED', 'VIRTUAL',
        ];
    }

    /**
     * Both quote characters, because on MySQL both open a string.
     *
     * The manual's String Literals section says a string is enclosed within either single quote or
     * double quote characters. `"` is an identifier quote only under `ANSI_QUOTES`, which is not in
     * the default `sql_mode` and which Laravel's MySQL connection does not set -- measured on 8.4.10,
     * `SELECT @@sql_mode` returns ONLY_FULL_GROUP_BY, STRICT_TRANS_TABLES, NO_ZERO_IN_DATE,
     * NO_ZERO_DATE, ERROR_FOR_DIVISION_BY_ZERO and NO_ENGINE_SUBSTITUTION, and no ANSI_QUOTES.
     *
     * This list was `["'"]` alone, and the cost was not theoretical in either direction. A valid
     * batch was REFUSED: `VALUES ("O'Brien"); ALTER TABLE …` opened a single-quote scan at the
     * apostrophe that ran to the end of the batch, and the splitter returned `unterminatedLiteral`
     * over SQL the server accepts. And a literal's content was read as syntax: `VALUES ("set
     * lock_wait_timeout = 5")` folded into the keyword pass and made MY.L3.MISSING_LOCK_WAIT_TIMEOUT
     * silent on a migration that never set a timeout.
     *
     * Laravel's grammar emits neither form. Raw SQL written by MySQL users emits both, and raw SQL is
     * what this package reads.
     *
     * The identifier quote is the backtick ({@see self::quotingCharacter()}), so nothing here is
     * ambiguous: a `"` opens data and a backtick opens a name.
     *
     * @return list<string>
     */
    public function stringLiteralDelimiters(): array
    {
        return ["'", '"'];
    }

    /**
     * The comment openers, with MySQL's double dash spelled out.
     *
     * MySQL reads `--` as a comment only when whitespace follows it: `1 --1` is one minus minus one.
     * A scanner that took it for a comment would hide the rest of that line as text the server never
     * runs, while the server runs it, and in a schema dump that is the line a `USE` can hide on. So
     * each whitespace that may follow the dashes is an opener of its own here, the same rule the
     * formatter's tokenizer applies, and a `--` with anything else after it stays SQL. A `--` that
     * ends the input with nothing after it stays text as well; there is nothing left for it to hide.
     *
     * `#` opens a line comment whatever follows it, and `/*` a block comment.
     *
     * @return list<string>
     */
    public function commentSyntaxes(): array
    {
        return ['-- ', "--\t", "--\n", "--\r", "--\v", "--\f", '/*', '#'];
    }

    public function supportsDdlTransactions(): bool
    {
        // MySQL commits DDL implicitly — a DDL statement is never rolled back with
        // the surrounding transaction.
        return false;
    }

    public function supportsDollarQuotedStrings(): bool
    {
        return false;
    }

    public function supportsDelimiterRedefinition(): bool
    {
        return true;
    }

    public function usesBackslashStringEscapes(): bool
    {
        return true;
    }

    public function nestsBlockComments(): bool
    {
        return false;
    }

    /**
     * The MySQL client has no line-directive syntax: `source other.sql` is a command it reads like
     * any other, not a prefix that changes where a statement ends. So there is nothing to declare —
     * and declaring a backslash anyway would be worse than saying nothing, because a backslash is a
     * live escape character inside a MySQL literal.
     */
    public function clientDirectivePrefix(): string
    {
        return '';
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
            closers: ['COMMIT', 'ROLLBACK'],
        );
    }

    public function statementClassification(): StatementClassificationProfile
    {
        $table = SchemaObjectType::Table;
        $index = SchemaObjectType::Index;
        $constraint = SchemaObjectType::Constraint;
        $column = SchemaObjectType::Column;

        return new StatementClassificationProfile(
            signatures: [
                // CREATE [UNIQUE] INDEX <i> ON <t>
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('CREATE'), SignatureElement::optionalModifiers(),
                    SignatureElement::keyword('INDEX'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($index),
                    SignatureElement::keyword('ON'), SignatureElement::target($table),
                ]),
                // CREATE TABLE [IF NOT EXISTS] <t> (<column definitions>)
                new StatementSignature(StatementKind::CreateTable, [
                    SignatureElement::keyword('CREATE'), SignatureElement::optionalModifiers(),
                    SignatureElement::keyword('TABLE'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($table),
                    SignatureElement::columnDefinitions(self::COLUMN_TYPE_TERMINATORS),
                ]),
                // DROP INDEX <i> ON <t>
                new StatementSignature(StatementKind::DropIndex, [
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('INDEX'),
                    SignatureElement::target($index),
                    SignatureElement::keyword('ON'), SignatureElement::target($table),
                ]),
                // DROP TABLE [IF EXISTS] <t> [, <t> …]
                //
                // Every name in the list is a target, as on PostgreSQL. TRUNCATE below keeps a single
                // one, because MySQL's TRUNCATE takes exactly one table and refuses a list.
                new StatementSignature(StatementKind::DropTable, [
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::targetList($table),
                ]),
                // TRUNCATE TABLE <t>  /  TRUNCATE <t>
                new StatementSignature(StatementKind::TruncateTable, [
                    SignatureElement::keyword('TRUNCATE'), SignatureElement::keyword('TABLE'),
                    SignatureElement::target($table),
                ]),
                new StatementSignature(StatementKind::TruncateTable, [
                    SignatureElement::keyword('TRUNCATE'), SignatureElement::target($table),
                ]),
                // ---------------------------------------------------------------------------
                // The ALTER TABLE shapes. ORDER IS BEHAVIOR here, not style: the two BARE forms at
                // the end (`ADD <c>` and `DROP <c>`) match any word after the keyword, so every
                // specific shape must be declared before them or its keyword is read as a column
                // name. Within that constraint the shapes are grouped ADD-then-DROP, except that
                // MODIFY/CHANGE and ADD COLUMN sit among the DROP block for historical reasons —
                // harmless, since they share no keyword with anything around them. Moving any of
                // them is safe ONLY while the two bare forms stay last; measure, do not assume.
                //
                // A second ordering holds inside the groups: a spelling that is the longer form of
                // another comes BEFORE it — `ADD UNIQUE KEY` before `ADD UNIQUE`, `MODIFY COLUMN`
                // before `MODIFY`. The shorter form would read the extra keyword as a name, and a
                // name slot holding a keyword fails the whole statement instead of passing it on to
                // the next signature.
                // ---------------------------------------------------------------------------
                // ALTER TABLE <t> ADD PRIMARY KEY (…)  — Laravel's primary(); carries no index name.
                // MySQL-only refinement: the PostgreSQL profile keeps AddConstraint, and its rules
                // never see a MySQL statement, so nothing downstream loses a match.
                new StatementSignature(StatementKind::AddPrimaryKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('PRIMARY'),
                    SignatureElement::keyword('KEY'),
                ]),
                // ALTER TABLE <t> ADD {INDEX|UNIQUE|FULLTEXT|SPATIAL} <i> (…) — the four index
                // shapes Laravel emits from index()/unique()/fullText()/spatialIndex(). Each is a
                // separate signature because the keyword differs; the resulting kind is the same.
                //
                // Beside them stand the manual's other spellings, which hand-written SQL uses as
                // often: `KEY` wherever `INDEX` may stand, and an optional `INDEX` or `KEY` after
                // UNIQUE, FULLTEXT and SPATIAL. Each longer spelling precedes the shorter one it
                // extends — the ordering rule above.
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('INDEX'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('KEY'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('UNIQUE'),
                    SignatureElement::keyword('INDEX'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('UNIQUE'),
                    SignatureElement::keyword('KEY'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('UNIQUE'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateFulltextIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('FULLTEXT'),
                    SignatureElement::keyword('INDEX'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateFulltextIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('FULLTEXT'),
                    SignatureElement::keyword('KEY'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateFulltextIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('FULLTEXT'),
                    SignatureElement::target($index),
                ]),
                // …and SPATIAL carries an `INDEX` keyword that FULLTEXT does not. Measured, after
                // this signature was first written by analogy with the one above and matched
                // nothing: the grammar emits `add spatial index `name`(…)` but `add fulltext
                // `name`(…)`. An unmatched signature is not a quiet miss — the statement becomes
                // uncanonicalizable and the whole migration reports CAP.L0.UNDETERMINED_CAPTURE, so
                // the run checks NOTHING for it.
                new StatementSignature(StatementKind::CreateSpatialIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('SPATIAL'),
                    SignatureElement::keyword('INDEX'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateSpatialIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('SPATIAL'),
                    SignatureElement::keyword('KEY'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateSpatialIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('SPATIAL'),
                    SignatureElement::target($index),
                ]),
                // ALTER TABLE <t> ADD CHECK (…)  /  ADD CONSTRAINT CHECK (…)  — a CHECK constraint
                // without a name; the server names it `<table>_chk_<n>`. `CHECK` is a reserved word
                // here, so it never names a column unquoted, and before it was a keyword the bare ADD
                // below read it as one: an added column called `CHECK`. Both shapes sit before every
                // `ADD CONSTRAINT <k>` one, whose target would otherwise meet the keyword and fail.
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CHECK'),
                ]),
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('CHECK'),
                ]),
                // ALTER TABLE <t> ADD CONSTRAINT PRIMARY KEY …  /  ADD CONSTRAINT UNIQUE [INDEX|KEY] <i> …
                // /  ADD CONSTRAINT FOREIGN KEY (<c>, …) REFERENCES <t2>  — the manual's
                // `ADD [CONSTRAINT [symbol]]` with the symbol left out. Each is read as the same
                // statement without `CONSTRAINT`, because the server makes the same object of it: the
                // primary key is `PRIMARY`, the unique index takes the name written after `UNIQUE`, and
                // the foreign key is named `<t>_ibfk_<n>`. Like the CHECK pair above, they sit before
                // every `ADD CONSTRAINT <k>` shape, whose target would meet the keyword and fail.
                new StatementSignature(StatementKind::AddPrimaryKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('PRIMARY'), SignatureElement::keyword('KEY'),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('INDEX'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('KEY'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('FOREIGN'), SignatureElement::keyword('KEY'),
                    SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // …and the same with the index name after `FOREIGN KEY`: the server keeps it for the
                // index and still names the constraint `<t>_ibfk_<n>`, as for `ADD FOREIGN KEY <i>`.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::keyword('FOREIGN'), SignatureElement::keyword('KEY'),
                    SignatureElement::target($index), SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE <t> ADD CONSTRAINT <k> PRIMARY KEY …  /  ADD CONSTRAINT <k> UNIQUE [INDEX|KEY] …
                // — the same with the symbol written, read for what the server keeps of it. A primary
                // key is `PRIMARY` whatever its symbol. A `UNIQUE` that names its index is that index,
                // and the symbol is dropped; one that names none takes the symbol as the index's name,
                // so there the symbol IS the index target. Without these shapes they fell to the
                // generic `ADD CONSTRAINT <k>` below, and no rule about a key or an index saw them.
                new StatementSignature(StatementKind::AddPrimaryKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::skippedName(),
                    SignatureElement::keyword('PRIMARY'), SignatureElement::keyword('KEY'),
                ]),
                // The index without a name of its own comes first: its column list follows the
                // keyword directly, and the named shapes below would read the first column as the
                // index's name.
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($index),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('INDEX'),
                    SignatureElement::columnList(),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($index),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('KEY'),
                    SignatureElement::columnList(),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($index),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::columnList(),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::skippedName(),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('INDEX'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::skippedName(),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::keyword('KEY'),
                    SignatureElement::target($index),
                ]),
                new StatementSignature(StatementKind::CreateIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::skippedName(),
                    SignatureElement::keyword('UNIQUE'), SignatureElement::target($index),
                ]),
                // ALTER TABLE <t> ADD CONSTRAINT <k> FOREIGN KEY (<c>, …) REFERENCES <t2>
                //
                // The columns travel, and they have to be read BEFORE the shape below, which is the
                // same statement without them. PostgreSQL's signature list has carried the pair this
                // way since the coverage rule needed it; MySQL's carried only the second, so a rule
                // asking a MySQL foreign-key statement for its columns got an empty list and said
                // nothing — which reads exactly like a schema whose keys are all named correctly.
                //
                // `seekKeyword('KEY')` rather than `FOREIGN`: the run stops at `REFERENCES`, so the
                // referenced table's own column list is never swept in. Two lists on one statement
                // would be indistinguishable afterwards and the wrong one would answer the question.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::seekKeyword('KEY'), SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // …and the same with the manual's optional index name after `FOREIGN KEY`. With a
                // symbol written, the server names the key's index after the symbol and drops this
                // name, so it is read past rather than taken as an index target. Without the shape the
                // column list above met the name, and the key arrived through the shape below with no
                // columns.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::keyword('FOREIGN'), SignatureElement::keyword('KEY'),
                    SignatureElement::skippedName(), SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE <t> ADD CONSTRAINT <k> … REFERENCES <t2> — the REFERENCES clause is
                // what makes this a foreign key rather than any other named constraint.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE <t> ADD FOREIGN KEY (<c>, …) REFERENCES <t2> — the manual's form without
                // a CONSTRAINT clause, where the server names the key itself (`<t>_ibfk_<n>`). It
                // carries no constraint target because the statement carries no name; the columns and
                // the referenced table travel exactly as in the named form above.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('FOREIGN'),
                    SignatureElement::keyword('KEY'), SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE <t> ADD FOREIGN KEY <i> (<c>, …) REFERENCES <t2>  — the same with the
                // manual's optional `index_name`. The server gives that name to the index the key
                // needs and still names the constraint `<t>_ibfk_<n>`, so the name is an index target,
                // and the statement carries no constraint target, as above.
                new StatementSignature(StatementKind::AddForeignKey, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('FOREIGN'),
                    SignatureElement::keyword('KEY'), SignatureElement::target($index),
                    SignatureElement::columnList(),
                    SignatureElement::seekKeyword('REFERENCES'), SignatureElement::target($table, TargetRole::Referenced),
                ]),
                // ALTER TABLE <t> ADD CONSTRAINT <k>
                new StatementSignature(StatementKind::AddConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::target($constraint),
                ]),
                // ALTER TABLE <t> DROP CONSTRAINT [IF EXISTS] <k>
                new StatementSignature(StatementKind::DropConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('CONSTRAINT'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($constraint),
                ]),
                // ALTER TABLE <t> DROP CHECK <k>  — the manual's form for a CHECK constraint. Before
                // `CHECK` was a keyword, the bare DROP at the end of this list took the word for a
                // column name and reported a dropped column `CHECK` with its data loss.
                new StatementSignature(StatementKind::DropConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('CHECK'),
                    SignatureElement::target($constraint),
                ]),
                // ALTER TABLE <t> MODIFY <c> …  /  CHANGE <c> <c2> …  — Laravel's ->change().
                // MODIFY keeps the name, CHANGE renames while redefining; both redefine a column,
                // which is the distinction that matters here. Placed before the bare ADD below,
                // though they cannot collide — different keywords.
                //
                // The manual allows `COLUMN` after either keyword, and hand-written SQL usually
                // writes it, so the spelled-out forms come first: the plain ones would read `COLUMN`
                // as the column's name.
                new StatementSignature(StatementKind::AlterColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('MODIFY'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                ]),
                new StatementSignature(StatementKind::AlterColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('CHANGE'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                ]),
                new StatementSignature(StatementKind::AlterColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('MODIFY'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($column),
                ]),
                new StatementSignature(StatementKind::AlterColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('CHANGE'), SignatureElement::optionalModifiers(),
                    SignatureElement::target($column),
                ]),
                // ALTER TABLE <t> ADD COLUMN <c> …  — the spelled-out form (hand-written SQL).
                new StatementSignature(StatementKind::AddColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                    // The type the column is added AS. Directly after the target, which is what
                    // pairs the two — see SignatureElementKind::TrailingColumnType.
                    SignatureElement::trailingColumnType(self::COLUMN_TYPE_TERMINATORS),
                ]),
                // ALTER TABLE <t> DROP PRIMARY KEY  (Laravel's dropPrimary; carries no name)
                new StatementSignature(StatementKind::DropConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('PRIMARY'),
                    SignatureElement::keyword('KEY'),
                ]),
                // ALTER TABLE <t> DROP FOREIGN KEY <k>  (Laravel's dropForeign)
                new StatementSignature(StatementKind::DropConstraint, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('FOREIGN'),
                    SignatureElement::keyword('KEY'), SignatureElement::target($constraint),
                ]),
                // ALTER TABLE <t> DROP INDEX <i>  (Laravel's dropIndex AND dropUnique)
                new StatementSignature(StatementKind::DropIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('INDEX'),
                    SignatureElement::target($index),
                ]),
                // ALTER TABLE <t> DROP KEY <i>  — the manual's synonym for the shape above.
                new StatementSignature(StatementKind::DropIndex, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('KEY'),
                    SignatureElement::target($index),
                ]),
                // ALTER TABLE <t> DROP COLUMN [IF EXISTS] <c>
                new StatementSignature(StatementKind::DropColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::keyword('COLUMN'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($column),
                ]),
                // ALTER TABLE <t> ADD <c> …  — the BARE form, and the one Laravel emits for a new
                // column. Same rule as the bare DROP below: it must sit after every specific ADD
                // shape (PRIMARY KEY, INDEX, KEY, UNIQUE, FULLTEXT, SPATIAL, CONSTRAINT, CHECK,
                // FOREIGN KEY, COLUMN), or it reads their keyword as a column name.
                new StatementSignature(StatementKind::AddColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('ADD'), SignatureElement::target($column),
                    // And here more than on the spelled-out form above: this is the shape Laravel
                    // actually emits, so it is the one nearly every added column arrives in.
                    SignatureElement::trailingColumnType(self::COLUMN_TYPE_TERMINATORS),
                ]),
                // ALTER TABLE <t> DROP <c>  — the BARE form, and the one Laravel actually emits for
                // dropColumn(). It must stay LAST of the DROP shapes: every specific one above
                // (PRIMARY KEY, FOREIGN KEY, INDEX, KEY, CONSTRAINT, CHECK, COLUMN) would otherwise be
                // read as a column named after its own keyword.
                new StatementSignature(StatementKind::DropColumn, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('DROP'), SignatureElement::target($column),
                ]),
                // ALTER TABLE <t> RENAME …
                new StatementSignature(StatementKind::Rename, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                    SignatureElement::keyword('RENAME'),
                ]),
                // RENAME TABLE <a> TO <b>
                new StatementSignature(StatementKind::Rename, [
                    SignatureElement::keyword('RENAME'), SignatureElement::keyword('TABLE'),
                    SignatureElement::target($table),
                ]),
                // ALTER TABLE <t> … (any other alter)
                new StatementSignature(StatementKind::AlterTable, [
                    SignatureElement::keyword('ALTER'), SignatureElement::keyword('TABLE'),
                    SignatureElement::optionalModifiers(), SignatureElement::target($table),
                ]),
                // INSERT INTO <t> …
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('INSERT'), SignatureElement::keyword('INTO'),
                    SignatureElement::target($table),
                ]),
                // UPDATE <t> SET <c> = <another column>, … — the targets of a data MOVE.
                //
                // BEFORE the plain `UPDATE <t>` below, because signatures are tried in order and the
                // plain one matches everything this does. It captures the columns a back-fill
                // WRITES, which is what the expand/contract debt rule needs; the columns it reads
                // sit inside expressions and stay there.
                //
                // Only assignments whose value mentions a column are captured: `SET status = 'new'`
                // gives a new column a value and is not a data move, and treating the two alike made
                // the PostgreSQL rule fire on the most ordinary migration there is.
                new StatementSignature(StatementKind::Dml, [
                    SignatureElement::keyword('UPDATE'), SignatureElement::target($table),
                    SignatureElement::keyword('SET'),
                    // MySQL ends a single-table UPDATE's SET clause with one of these three. It has
                    // no `FROM` in that position and no `RETURNING` at all — the two engines differ
                    // here, which is why the terminators come from the driver rather than the core.
                    SignatureElement::backfillTargets(['WHERE', 'ORDER', 'LIMIT']),
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
            modifiers: ['UNIQUE', 'IF', 'NOT', 'EXISTS'],
            leadFallback: [
                'CREATE' => StatementKind::DdlOther,
                'ALTER' => StatementKind::DdlOther,
                // `DROP SCHEMA` lands here on purpose, where PostgreSQL gives it its own kind.
                //
                // The words are the same and the object is not: in MySQL `SCHEMA` is a SYNONYM for
                // `DATABASE`, so `DROP SCHEMA app` drops a database, while in PostgreSQL it drops a
                // namespace inside one. A rule written for the second and applied to the first would
                // be confident, specific and about another thing — which is the failure this package
                // refuses by name elsewhere.
                //
                // So MySQL gets no `DropSchema` signature until it gets a rule of its own, with its
                // own text: dropping a MySQL database is a bigger act than dropping a PostgreSQL
                // schema, and DDL here is not transactional, so the implicit commit makes it final
                // the instant it runs.
                'DROP' => StatementKind::DdlOther,
                'TRUNCATE' => StatementKind::DdlOther,
                'RENAME' => StatementKind::DdlOther,
                'INSERT' => StatementKind::Dml,
                'UPDATE' => StatementKind::Dml,
                'DELETE' => StatementKind::Dml,
                'SELECT' => StatementKind::Unknown,
                // A session config command. Measured before it was added: without this entry a
                // `SET foreign_key_checks = 0` — an ordinary line in a MySQL migration — was
                // UNCANONICALIZABLE, so the whole migration reported CAP.L0.UNDETERMINED_CAPTURE
                // and nothing in it was checked. Never a silent green, but a real hole, and the
                // PostgreSQL profile had recognized the same form all along.
                'SET' => StatementKind::SessionSetting,

                // The privilege grammar — the same hole as the `SET` one above, found the same way
                // and two engines wide this time. Measured: `GRANT SELECT ON app.orders TO
                // 'app'@'%'` was UNRECOGNIZED_STATEMENT_FORM on both drivers, so no subject was
                // ever built and no migration-security rule over a GRANT could fire in a real run.
                //
                // `DdlOther` matches what `ALTER DEFAULT PRIVILEGES … GRANT …` already received via
                // its `ALTER` lead, so one privilege operation does not carry two kinds depending
                // on how it was spelled.
                //
                // `CREATE USER` and `DROP USER` need no entry: they lead with CREATE and DROP,
                // which this table already maps. That asymmetry is worth stating, because it is
                // why the hole was invisible — the statements AROUND a grant canonicalized fine.
                'GRANT' => StatementKind::DdlOther,
                'REVOKE' => StatementKind::DdlOther,
            ],
            // `ALTER TABLE t ADD INDEX i (a), ALGORITHM=INPLACE, LOCK=NONE`: the last two qualify how
            // the index is built and are not actions of their own.
            actionOptions: ['ALGORITHM', 'LOCK'],
            unreservedNames: self::UNRESERVED_NAMES,
            // `ALTER TABLE t ADD (a INT, b INT)` adds two columns, the manual's
            // `ADD [COLUMN] (col_name column_definition, ...)`.
            parenthesizedAddColumns: true,
        );
    }
}
