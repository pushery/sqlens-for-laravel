<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Which process started which, read once.
 *
 * A tool that is stopped takes its descendants with it, and they are found through this table
 * while their parent still links them to the run: once that parent is gone, an orphan's parent is
 * init, and nothing connects it to the tool any more. Linux publishes the table under `/proc`, and
 * `ps` prints it everywhere else. This class only reads what it is given and starts no process of
 * its own; {@see SystemProcessRunner} is the one place that does.
 *
 * A table that cannot be read is an empty one, and an empty table leaves a stop as it was before
 * this class existed: the tool itself is still stopped.
 */
final readonly class ProcessTable
{
    /** @param array<int, list<int>> $children each parent pid with the pids it started */
    private function __construct(private array $children) {}

    /** No table, for a platform whose own stop already takes the whole tree. */
    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * The table a `/proc` describes, one `<pid>/stat` per process.
     *
     * The parent is read after the LAST closing parenthesis. The second field is the command name
     * in parentheses, and a name may hold spaces and parentheses of its own, so splitting the line
     * on whitespace from its start would read a word of the name as the parent.
     */
    public static function fromProc(string $root): self
    {
        $pairs = [];

        foreach (glob($root.'/[0-9]*/stat') ?: [] as $file) {
            // A process can end between the listing and the read. Its line is then empty, which
            // reads as pid 0 and is dropped below with every other line that names no process.
            $stat = (string) @file_get_contents($file);
            $fields = preg_split('/\s+/', trim(substr($stat, (int) strrpos($stat, ')') + 1))) ?: [];
            $pairs[] = [(int) $stat, (int) ($fields[1] ?? 0)];
        }

        return self::of($pairs);
    }

    /** The table `ps -A -o pid= -o ppid=` prints: a pid and its parent on every line. */
    public static function fromPsOutput(string $output): self
    {
        preg_match_all('/^\s*(\d+)\s+(\d+)\s*$/m', $output, $rows, PREG_SET_ORDER);

        return self::of(array_map(static fn (array $row): array => [(int) $row[1], (int) $row[2]], $rows));
    }

    /**
     * Every process below `$pid`, nearest first.
     *
     * @return list<int>
     */
    public function descendantsOf(int $pid): array
    {
        $found = [];
        $queue = $this->children[$pid] ?? [];

        while ($queue !== []) {
            $next = array_shift($queue);

            if ($next !== $pid && ! in_array($next, $found, true)) {
                $found[] = $next;
                $queue = [...$queue, ...($this->children[$next] ?? [])];
            }
        }

        return $found;
    }

    /** @param list<array{int, int}> $pairs a pid and its parent */
    private static function of(array $pairs): self
    {
        $children = [];

        foreach ($pairs as [$pid, $parent]) {
            // Never 0 or 1 as a child. `kill` reads 0 as the caller's whole process group, and 1 is
            // init; a line that parsed to either names no process this run started.
            if ($pid > 1 && $pid !== $parent) {
                $children[$parent][] = $pid;
            }
        }

        return new self($children);
    }
}
