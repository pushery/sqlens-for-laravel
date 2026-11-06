<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Closure;
use InvalidArgumentException;
use Pushery\SQLens\Guard\Guards\RuntimeDdlGuard;

/**
 * Schema changes a running application makes on purpose, declared with the reason it makes them.
 *
 *     app(ExpectedSchemaChanges::class)->during(
 *         reason: 'the monthly partitions of the ledger, for the months the demo history writes into',
 *         work: fn () => $partitions->ensure($from),
 *     );
 *
 * The runtime DDL guardrail ({@see RuntimeDdlGuard}) reports a schema change outside any migration, and a job that
 * creates the partition of the month ahead makes exactly that change, on purpose. While the declared work runs, the
 * guardrail reports no DDL. Before it and after it, the guardrail reports as before, also after work that threw, and a
 * declaration inside another one ends only itself.
 *
 * A declaration covers a block of work in this process, never a form of statement: the same `CREATE TABLE … PARTITION
 * OF` from a request outside the block is still reported. It costs nothing where no guardrail is armed, so the code
 * that declares does not ask whether one is.
 */
final class ExpectedSchemaChanges
{
    /**
     * The reasons of the declarations under way in this process, the outermost first.
     *
     * @var list<string>
     */
    private array $reasons = [];

    /**
     * Runs the work as a declared schema change and hands back what it returns.
     *
     * @template TResult
     *
     * @param  string  $reason  why the work changes the schema, written for whoever reads the code that declares it
     * @param  Closure(): TResult  $work
     * @return TResult
     *
     * @throws InvalidArgumentException when the reason is empty
     */
    public function during(string $reason, Closure $work): mixed
    {
        if (trim($reason) === '') {
            throw new InvalidArgumentException('A declared schema change names the reason it is made.');
        }

        $this->reasons[] = $reason;

        try {
            return $work();
        } finally {
            array_pop($this->reasons);
        }
    }

    /**
     * Whether declared work is running in this process.
     */
    public function underWay(): bool
    {
        return $this->reasons !== [];
    }
}
