<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Pushery\SQLens\Config\ProfileApplication;
use Pushery\SQLens\Console\ExitCode;

/**
 * The answer to a tool call whose profile could not be chosen, given before any run started.
 *
 * The command names an unknown or empty profile and stops as a misconfiguration. A tool that fell
 * back to the lenient default instead would answer the stricter question it was asked with a laxer
 * verdict, so the call is undetermined: the value, where it was set, and the names that would have
 * been accepted.
 */
final readonly class ProfileRefusal
{
    /**
     * @param  string  $rejected  the value that named no known profile
     * @param  string  $source  where it was set, in the selector's words: `flag`, `env` or `config`
     */
    public static function answer(string $rejected, string $source): ToolAnswer
    {
        // The selector's `flag` is this layer's parameter. The two defaults below the user-set
        // sources name known profiles by construction, so a rejection comes from one of three.
        [$origin, $words] = match ($source) {
            'flag' => ['parameter', 'the profile parameter'],
            'env' => ['env', 'the SQLENS_PROFILE environment variable'],
            default => ['config', 'sqlens.profile'],
        };

        return ToolAnswer::undetermined(
            sprintf(
                'nothing was checked: the profile "%s" set by %s is not one this package knows. Available profiles: %s.',
                $rejected,
                $words,
                implode(', ', ProfileApplication::names()),
            ),
            ['refusal' => ['id' => 'unknown_profile', 'profile' => $rejected, 'source' => $origin]],
        );
    }

    /**
     * The whole answer of a lint tool: the refusal, and a gate block saying it is breached with
     * the exit code the command stops on.
     *
     * @return array<string, mixed>
     */
    public static function forLint(string $rejected, string $source): array
    {
        return [
            ...self::answer($rejected, $source)->toArray(),
            'gate' => [
                'breached' => true,
                'exit_code' => ExitCode::Misconfiguration->value,
                'meaning' => ExitCode::Misconfiguration->description(),
            ],
        ];
    }
}
