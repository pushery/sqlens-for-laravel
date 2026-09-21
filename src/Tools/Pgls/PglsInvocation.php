<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * The knobs one `dblint` run is given, gathered so the runner never reads configuration itself.
 *
 * Small, because this tool takes far less steering than Squawk does: it reads a schema that is
 * already there, so there is no server version to assume and no transaction model to declare. The
 * one thing it genuinely needs is WHICH database — and that is required rather than defaulted,
 * for the reason spelled out on {@see PglsConnection}.
 */
final readonly class PglsInvocation
{
    public function __construct(
        public PglsConnection $connection,
        /**
         * The bound one invocation gets before it is reported as timed out.
         *
         * Longer than Squawk's, and measured rather than guessed: this tool opens a connection and
         * runs sixteen catalog queries, where Squawk parses text in memory. A warm local run took
         * ~2.6s against a small database; a bound near that would turn a slightly larger schema
         * into a timeout, and a timeout is an undetermined — the run would lose the checks for a
         * reason that is not a problem.
         */
        public float $timeoutSeconds = 30.0,
        /**
         * The NAME of the connection, for anything this adapter has to say about it.
         *
         * Carried beside the coordinates rather than derived from them, because a failure message
         * is read by somebody holding this project's configuration: they find the host under this
         * name, and a report that repeated the host, the port and the database instead would tell
         * them nothing they cannot look up while carrying an address off the machine. The value
         * class deliberately has no name of its own — it is what the tool needs to CONNECT, and a
         * label is not part of that.
         *
         * Defaulted so the one call site that builds a throwaway invocation purely to read the
         * default timeout does not have to invent one.
         */
        public string $connectionName = '',
    ) {}
}
