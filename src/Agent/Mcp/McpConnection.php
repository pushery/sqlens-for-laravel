<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Illuminate\Contracts\Config\Repository;

/**
 * Which connection an MCP tool answers about, read from `sqlens.agent.mcp.connection`.
 *
 * Unset, a tool runs against the application's default connection, and a client may name any
 * connection the application has configured. Set, the tools run against that connection when the
 * client names none, and it is the only name the `connection` argument accepts: a project that
 * points its server at one connection gets answers about that one and no other.
 *
 * One reading for every tool that takes the argument, so no two tools can disagree about which
 * connection a client may name.
 */
final readonly class McpConnection
{
    public function __construct(private Repository $config) {}

    /**
     * The names a client may pass as `connection`.
     *
     * @return list<string>
     */
    public function allowed(): array
    {
        $configured = $this->configured();

        if ($configured !== null) {
            return [$configured];
        }

        $connections = $this->config->get('database.connections');

        return array_values(array_filter(
            array_map(strval(...), array_keys(is_array($connections) ? $connections : [])),
            static fn (string $name): bool => $name !== '',
        ));
    }

    /**
     * The connection a tool runs against: the one the client named, else the configured one, else
     * null for the application's default.
     */
    public function chosen(mixed $requested): ?string
    {
        return is_string($requested) && $requested !== '' ? $requested : $this->configured();
    }

    private function configured(): ?string
    {
        $configured = $this->config->get('sqlens.agent.mcp.connection');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }
}
