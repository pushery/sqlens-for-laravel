<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The contract every reporter writes against — console and JSON today, GitHub
 * annotations, SARIF, and `--format=agent` later. A reporter RENDERS a result; it
 * does NOT decide the exit code. That separation is deliberate: presentation and
 * the gate contract are different concerns, so the exit-code derivation is its own
 * contract and never leaks into how a result is displayed.
 *
 * A reporter must know nothing driver-specific — it renders the neutral Result and
 * RunContext, so the same reporter serves both PostgreSQL and MySQL runs.
 */
interface Reporter
{
    /** The format name this reporter answers to (e.g. `console`, `json`). */
    public function name(): string;

    /** Render the result and its run context to the given output. */
    public function report(Result $result, RunContext $context, OutputInterface $out): void;
}
