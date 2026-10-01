<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\Stages\StatementSplitter;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;

/**
 * A PostgreSQL `schema:dump` artifact as the statements a shadow template is built from.
 *
 * Laravel writes the file with `pg_dump` in two runs, `--schema-only` and then, once a migrations
 * table exists, `-t <migrations table> --data-only` appended to it, and it loads the file back with
 * `psql --file`. The file is therefore psql's input rather than plain SQL, in two ways a server
 * reading it directly refuses:
 *
 * - Current `pg_dump`, 18.4 and 16.13 among them, opens and closes each run with the psql
 *   meta-commands `\restrict` and `\unrestrict`.
 * - Rows arrive as `COPY … FROM stdin;`, followed by tab-separated lines up to one holding `\.`.
 *
 * Both are read here the way psql reads them, for a template that holds structure and no rows. A
 * meta-command is a client directive, and the splitter leaves it out. A `COPY … FROM stdin` block is
 * left out whole, command, rows and terminator: the only rows the file carries are the migrations
 * table's, and the shadow runner calls each migration directly, so no run ever reads them. Everything
 * else is returned in file order, one statement each, split by the same splitter the canonicalization
 * uses, so a semicolon inside a literal or a dollar-quoted body never ends a statement.
 */
final readonly class PgsqlSchemaDump
{
    /** The command line that opens a block of rows, as `pg_dump` writes it. */
    private const string COPY_FROM_STDIN = '/^COPY\s.+\sFROM\s+stdin;\s*$/i';

    public function __construct(private StatementSplitter $splitter = new StatementSplitter) {}

    /**
     * The statements to replay, in file order, or null when the text cannot be read safely: a literal
     * that never closes, or a block of rows that never reaches its `\.`.
     *
     * @return list<string>|null
     */
    public function statements(string $dump): ?array
    {
        $structure = $this->withoutRows($dump);

        if ($structure === null) {
            return null;
        }

        $statements = $this->splitter->split($structure, new PgsqlCanonicalization);

        if ($statements instanceof CanonicalizationFailure) {
            return null;
        }

        // A part that is nothing but comments is left out. `pg_dump` ends each run with one, and a
        // server handed it on its own answers with an error rather than with nothing.
        return array_values(array_filter(
            $statements,
            static fn (string $statement): bool => trim((string) preg_replace('/--[^\n]*|\/\*.*?\*\//s', '', $statement)) !== '',
        ));
    }

    /**
     * The dump without its `COPY … FROM stdin` blocks, or null when one runs to the end of the file.
     *
     * psql would read such a block as rows up to the end, so nothing after its command line is a
     * statement, and replaying the part before it would build half a schema.
     */
    private function withoutRows(string $dump): ?string
    {
        $kept = [];
        $inRows = false;

        foreach (explode("\n", $dump) as $line) {
            $content = rtrim($line, "\r");

            if ($inRows) {
                $inRows = $content !== '\.';

                continue;
            }

            if (preg_match(self::COPY_FROM_STDIN, $content) === 1) {
                $inRows = true;

                continue;
            }

            $kept[] = $line;
        }

        return $inRows ? null : implode("\n", $kept);
    }
}
