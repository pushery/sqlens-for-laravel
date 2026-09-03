<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

/**
 * The `--strict-tools` / `--no-strict-tools` pair, resolved once for every command that offers it.
 *
 * Strict tool mode decides what a MISSING capability means: an error, or a degradation the run
 * carries on without. That is a real difference to a pipeline — a lint run whose external analyzer
 * is not installed either fails loudly or reports fewer findings than it looks like it reported.
 *
 * The pair exists rather than a single flag because a project configures `strict_tools` once and
 * both directions have to be overridable from the command line. `--strict-tools` forces it on for
 * this run, `--no-strict-tools` forces it off, and neither leaves the configured value alone.
 *
 * Shared rather than written twice. Two commands each parsing the same pair is two chances to
 * disagree about the precedence below, and the disagreement would be invisible: both would still
 * run, and only the one a user happened to pick would behave the way the docs describe.
 */
trait ResolvesStrictTools
{
    /**
     * Whether this run forces strict tool mode on, off, or leaves it to the configuration.
     *
     * ON wins when somebody passes both. There is no reading of "strict and not strict" that is
     * true, so the choice is which mistake to make — and the stricter one surfaces a missing tool
     * instead of quietly checking less than the caller asked for.
     */
    private function strictToolsOverride(): ?bool
    {
        if ($this->option('strict-tools') === true) {
            return true;
        }

        if ($this->option('no-strict-tools') === true) {
            return false;
        }

        return null;
    }
}
