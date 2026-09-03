<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Capture;

use Pushery\SQLens\Contracts\BindingFormatter;

/**
 * MySQL's binding literals.
 *
 * MySQL has no dedicated boolean type — `TRUE`/`FALSE` are aliases for `1`/`0`,
 * and the canonical rendering is the integer. Emitting the keyword would survive
 * here but diverge from what the engine actually stores, and the canonical form
 * has to match the engine, not the spelling a developer might use.
 */
final readonly class MysqlBindingFormatter implements BindingFormatter
{
    public function booleanLiteral(bool $value): string
    {
        return $value ? '1' : '0';
    }

    public function dateFormat(): string
    {
        return 'Y-m-d H:i:s';
    }
}
