<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Capture;

use Pushery\SQLens\Contracts\BindingFormatter;

/**
 * PostgreSQL's binding literals.
 *
 * `true`/`false` are real keywords here, not integers — writing `1` would still
 * parse against an integer column and silently mean something else.
 */
final readonly class PgsqlBindingFormatter implements BindingFormatter
{
    public function booleanLiteral(bool $value): string
    {
        return $value ? 'true' : 'false';
    }

    public function dateFormat(): string
    {
        return 'Y-m-d H:i:s';
    }
}
