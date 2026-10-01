<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Laravel\Mcp\Server\ToolInvoker;
use Override;
use PDOException;
use Throwable;

/**
 * Invokes a tool the way the SDK does, and answers a failure with what failed rather than its message.
 *
 * The SDK answers with the exception's message whenever the host application runs with `app.debug`
 * on, which is Laravel's default on the machine an MCP client usually runs on. A database error's
 * message is the one this package takes the most care over: Laravel appends the connection's host,
 * port and database and the statement with its bindings written in, and a tool answer goes to the
 * client and to the model behind it.
 *
 * So the answer names the kind of failure and, for a database error, its SQLSTATE. That is enough to
 * act on (a missing privilege is `42501`, a statement that ran out of time `57014`), and it carries
 * no text the server wrote. The whole exception goes to the application's log, where its other errors
 * go.
 */
final class WithholdingToolInvoker extends ToolInvoker
{
    #[Override]
    protected function toErrorMessage(Throwable $e): string
    {
        Container::getInstance()->make(ExceptionHandler::class)->report($e);

        $state = $e instanceof PDOException && is_string($e->errorInfo[0] ?? null) ? $e->errorInfo[0] : null;

        return sprintf(
            'The tool failed with %s%s. Its message is withheld from this answer, because a database error '
            .'carries the connection\'s address and the statement\'s values; the whole error is in the '
            .'application\'s log.',
            $e::class,
            $state === null ? '' : ' (SQLSTATE '.$state.')',
        );
    }
}
