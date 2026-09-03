<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Lint\LintOutcome;

/**
 * A run the engine never performed, turned into the only answer such a run may have.
 *
 * ## The failure this exists to close
 *
 * Measured, on the real tool, twice: an unsupported engine and a `file` outside the configured
 * migration paths both came back as
 *
 *     status: "ok", undetermined_reasons: [], summary: "No findings on testing."
 *
 * beside a gate block that said `exit_code: 2` and *the configuration is invalid; nothing was
 * audited*. One answer contradicting itself, with the three-valued field — the one an agent reads —
 * saying the wrong half. An agent reading that reports the migration clean and moves on, which is
 * the most expensive path this package exists to prevent.
 *
 * ## Why the exit code and not the two named failures
 *
 * `LintOutcome` carries `unsupported` and `fileFailure`, and both are used below for the REASON.
 * But neither is what decides: a misconfiguration exit is reachable without either — an invalid
 * config, an unreadable baseline, a strict-tool stop — and a check written against the two known
 * causes would go quiet again the first time a third arrived. The exit code is the engine's own
 * summary of "nothing was audited", so it is the condition, and the failures only sharpen the
 * sentence.
 *
 * ## Why it is not a method on the tool
 *
 * Three tools start a run — `lint_pending` now, `lint_shadow` and `predeploy` next — and a check
 * copied into each is a check two of them can be written without. This is the one place, and it is
 * the reason a new run-starting tool cannot reintroduce the silent green by omission.
 *
 * Nothing here invents a reason. The identifiers come from the engine's own named failures and stay
 * stable English, exactly as they are in the JSON envelope: a translated reason id would be a
 * breaking change per language.
 */
final readonly class RunRefusal
{
    /**
     * The answer a run that never happened must give — or null when the run really ran.
     *
     * Null rather than a "not refused" object: the caller's next step is its ordinary answer, and a
     * sentinel it had to unwrap would be one more thing to get wrong in the direction that hurts.
     */
    public static function in(LintOutcome $outcome): ?ToolAnswer
    {
        if ($outcome->exitCode !== ExitCode::Misconfiguration) {
            return null;
        }

        [$id, $detail] = self::cause($outcome);

        return ToolAnswer::undetermined(
            $detail,
            // Structured beside the sentence, because an agent acts on fields. The sentence is for
            // a client that shows text; `refusal.id` is what something branches on, and it is the
            // engine's own identifier rather than a second vocabulary invented here.
            ['refusal' => ['id' => $id, 'connection' => $outcome->connectionName]],
        );
    }

    /**
     * The engine's own name for what stopped this run, and the sentence that goes with it.
     *
     * @return array{0: string, 1: string}
     */
    private static function cause(LintOutcome $outcome): array
    {
        // `!== null` rather than `instanceof`, and that is not a style lapse: naming the type would
        // import `Drivers\…` and `Capture\…` into the agent layer, which its architecture test
        // forbids — the layer must not be able to name the engine's internals. Rector suggests the
        // flip and is wrong here for a reason that only shows up one directory away, so the rule is
        // skipped for this file with that reason written down in rector.php.
        if ($outcome->unsupported !== null) {
            return [
                $outcome->unsupported->reason->value,
                'nothing was checked on connection "'.$outcome->connectionName.'": '.$outcome->unsupported->detail,
            ];
        }

        if ($outcome->fileFailure !== null) {
            return [
                $outcome->fileFailure->value,
                // No backticks in this sentence, and that is not a style choice: the agent layer's
                // architecture test refuses a shell backtick anywhere in these files, and its pattern
                // cannot tell one inside a string from one that would execute. Blunt in the safe
                // direction, so the sentence gives way rather than the guard.
                'the file did not resolve to a migration this project lints ('.$outcome->fileFailure->value
                .'), so nothing was checked. The file parameter names one migration under a configured '
                .'migration path — it is not a general-purpose file linter.',
            ];
        }

        // The catch-all, and it is the whole reason the condition is the exit code. A cause this
        // build cannot name yet still produces a refusal rather than a pass.
        return ['misconfiguration', $outcome->exitCode->description().' Nothing about the migrations was determined.'];
    }
}
