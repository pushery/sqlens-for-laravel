<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Agent\Mcp\McpProtocol;
use Pushery\SQLens\Agent\Mcp\McpToolPolicy;
use Pushery\SQLens\Agent\Mcp\ServesMcp;
use Pushery\SQLens\Agent\Mcp\ToolRegistry;
use Pushery\SQLens\Agent\Mcp\Tools\SqlensTool;
use Pushery\SQLens\Config\ConfigSchema;
use Symfony\Component\Console\Output\ConsoleOutputInterface;

/**
 * `sqlens:mcp` — starts the MCP server on this process's stdin and stdout.
 *
 * ## Why the package owns the command instead of using the SDK's
 *
 * `laravel/mcp` ships `mcp:start <handle>`, which resolves a server an application registered in
 * its own `routes/ai.php`. A package does not own that file, and a consuming application should
 * not have to edit it to get a capability the package already has. So the command is ours, the
 * server is constructed here, and the application configures it through `sqlens.agent.mcp` like
 * every other part of this package.
 *
 * ## Why it degrades instead of failing
 *
 * The SDK is optional and deliberately not required — it pulls `illuminate/routing` and a Symfony HTTP stack
 * along for a server that speaks stdio only, and an application running `sqlens:lint` in a deploy
 * pipeline should not pay for that. So the dependency can genuinely be absent, and its absence is
 * reported as a NAMED reason with the command that fixes it, never as a class-not-found trace. It
 * is the same three-valued discipline the rest of the package applies to a missing external tool:
 * "this could not run, and here is why" is a different sentence from "this failed".
 *
 * ## Why stdout is never written to here
 *
 * Everything this command has to say goes to stderr. The frame stream on stdout belongs to the
 * protocol alone: one stray line — a startup banner, a deprecation notice, a forgotten dump — and
 * the client's parser desynchronizes on a message it cannot read, which looks to a user like the
 * server is broken rather than like something printed a sentence.
 */
final class McpCommand extends Command
{
    /**
     * One option, and it names its tool every time.
     *
     * `--connection=` and `--profile=` are deliberately absent: both belong to the TOOLS, which take
     * them as arguments, and an option a run accepts and then ignores is the silent no-op this
     * package refuses everywhere else.
     *
     * There is no `--enable-all`. Not an omission — a master switch turns a decision about one
     * dangerous capability into a decision about every one this package will ever have, including
     * the ones added after somebody flipped it.
     */
    protected $signature = 'sqlens:mcp
        {--enable-tool=* : Expose one mutating tool for this run, by name. Repeatable; there is no option that enables them all.}';

    protected $description = 'Start the SQLens MCP server on stdio, for an AI agent to call.';

    public function handle(Repository $config, ServesMcp $server): int
    {
        if (! $server->isAvailable()) {
            // Named, actionable, and on stderr. A trace here would tell a user that a class is
            // missing; this tells them which package provides it and that installing it is all
            // that is needed.
            $this->outputErrorLine(
                'The MCP server needs laravel/mcp, which is not installed. It is an optional '
                .'dependency rather than a required one, because it brings an HTTP stack that a '
                .'run without the server never uses. Install it with: composer require --dev laravel/mcp'
            );

            return ExitCode::Misconfiguration->value;
        }

        if ($config->get('sqlens.agent.mcp.transport') !== 'stdio') {
            // The configuration validator already refuses anything else, so reaching this means it
            // was bypassed. Refusing again rather than falling back to stdio: a project that wrote
            // a different transport asked for something this build cannot do, and quietly giving
            // them a different one is the answer they cannot check.
            $this->outputErrorLine(
                'This build speaks only the stdio transport. Set sqlens.agent.mcp.transport to "stdio".'
            );

            return ExitCode::Misconfiguration->value;
        }

        // What this run REALLY exposed, named before a client connects rather than after it asks.
        //
        // From the registry filtered by the policy, not from the policy alone — and that is a
        // correction rather than a preference. The policy answers "which names may be on", which
        // includes tools this build has not written yet: the first version of this line announced
        // four tools while `tools/list` returned one. An operator line that overstates the surface
        // is the same silent green as a report that understates a finding.
        $enables = $this->requestedTools();

        if ($enables === false) {
            return ExitCode::Misconfiguration->value;
        }

        $server->enableForSession($enables);

        $policy = McpToolPolicy::fromConfig($config->get('sqlens.agent.mcp.tools'))->alsoEnabling($enables);

        // Bound HERE, where the container is already in hand, so the listing, the banner and the
        // `tools/call` handler all read one object. The loop reads it back rather than rebuilding
        // it: a second policy would be a second answer about which tools this session exposes.
        $this->laravel->instance(McpToolPolicy::class, $policy);

        $exposed = ToolRegistry::declared()->exposedTo($policy);

        $this->outputErrorLine(sprintf(
            'SQLens MCP server on stdio, protocol %s. Tools exposed: %s.',
            McpProtocol::VERSION,
            implode(', ', array_map(static fn (SqlensTool $tool): string => $tool->name(), $exposed)) ?: 'none',
        ));

        // Named separately and every session. Somebody who enabled a tool that CHANGES something
        // should see it in the log of every run, not only in the one where they turned it on — a
        // capability enabled six months ago and forgotten is the one that surprises people.
        $mutating = $policy->enabledMutating();

        $this->outputErrorLine($mutating === []
            ? '[sqlens:mcp] No mutating tool is enabled. Nothing this server exposes can change anything.'
            : '[sqlens:mcp] MUTATING tools enabled for this run: '.implode(', ', $mutating).'.');

        // Nothing before this line opened a connection, and nothing here does either: the loop
        // reads frames and dispatches them, and a database is touched only inside the service a
        // tool call reaches, for the length of that call.
        //
        // It returns when the client goes away. A server that held a conversation and then said
        // its own run had failed would be inventing a verdict about something that already ended.
        $ending = $server->serve();

        // Every way out of a run is NAMED, on the diagnostic channel, before the process reports
        // its code. A silent exit 0 reads to every log reader as a clean end — and it is exactly
        // the signature a read timeout mistaken for a hangup produced.
        $this->outputErrorLine('[sqlens:mcp] '.$ending->reason().'.');

        return $ending->code();
    }

    /**
     * The tools this run was asked to enable, or false when one of them is not a tool.
     *
     * Refused LOUDLY rather than ignored. Somebody typing `--enable-tool=predploy` believes they
     * enabled a deploy gate; a run that started anyway with the tool still off would be the most
     * expensive kind of quiet — they would act on an answer no tool ever produced.
     *
     * @return list<string>|false
     */
    private function requestedTools(): array|false
    {
        $names = array_values(array_filter($this->option('enable-tool'), is_string(...)));
        $unknown = array_values(array_diff($names, ConfigSchema::MCP_TOOL_NAMES));

        if ($unknown !== []) {
            $this->outputErrorLine(sprintf(
                'Not a tool this build knows: %s. Known tools: %s.',
                implode(', ', $unknown),
                implode(', ', ConfigSchema::MCP_TOOL_NAMES),
            ));

            return false;
        }

        return $names;
    }

    /**
     * Everything that is not a protocol frame goes to STDERR — stdout belongs to the protocol.
     *
     * Written the same way `sqlens:postdeploy` writes its non-report output, deliberately: two
     * spellings of "this goes to the error stream" is two places for one of them to stop doing it.
     */
    private function outputErrorLine(string $line): void
    {
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($line);
    }
}
