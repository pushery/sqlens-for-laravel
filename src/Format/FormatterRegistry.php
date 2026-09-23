<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Pushery\SQLens\Contracts\SqlFormatter;

/**
 * Which backend formats, resolved from a name and a dialect — and never by trying one to find out.
 *
 * ## `auto` picks the best AVAILABLE backend, in a written order
 *
 * pgFormatter and SQLFluff both know more SQL than the built-in core, so `auto` prefers them where
 * they are installed and answer for the dialect. The order is a list in this class rather than a
 * discovered one: a preference that depended on which adapter happened to register first would make
 * two identical projects format differently, and the output is committed.
 *
 * ## A NAMED backend is never silently substituted
 *
 * Asking for `pgformatter` and getting the PHP core because the binary is missing would produce
 * output a project did not ask for and no signal that it had happened — and the next machine, where
 * the binary IS installed, would rewrite every file. A named backend that cannot run is a refusal
 * with its reason, and only `auto` falls back.
 */
final readonly class FormatterRegistry
{
    /**
     * The preference order for `auto`, best first.
     *
     * @var list<string>
     */
    public const array AUTO_ORDER = ['pgformatter', 'sqlfluff', 'php'];

    /**
     * @param  list<SqlFormatter>  $formatters
     * @param  list<string>  $disabled  backends this project decided to do without — see
     *                                  {@see FormatConfig::$disabledBackends}. They are kept OUT of
     *                                  the registry rather than filtered inside it, so `auto` never
     *                                  reaches them and never counts them as a loss; this list
     *                                  survives only so a NAMED one can be refused with the true
     *                                  reason instead of "no such backend".
     */
    public function __construct(private array $formatters = [], private array $disabled = []) {}

    /**
     * The backend for a request, or a named reason there is none.
     *
     * There is no "unknown dialect" case to handle here. No backend is safe to run blind, the
     * built-in core included: `SqlTokenizer` switches comment syntax on the dialect and `SqlToken`
     * switches keyword case on it. `sqlens:format` refuses an unresolved dialect up front, so every
     * dialect reaching this method is one somebody named.
     *
     * @param  string  $requested  a backend name, or `auto`
     */
    public function resolve(string $requested, Dialect $dialect, FormatStyle $style): FormatterResolution
    {
        if ($requested !== 'auto') {
            $named = $this->byName($requested);

            // Named AND switched off by this project — a contradiction, and it gets its own sentence
            // rather than the "no such backend" one below. Those are different mistakes: one is a
            // typo, the other is a project asking for the thing it decided to do without, and a
            // reader told the wrong one goes looking in the wrong file.
            if (! $named instanceof SqlFormatter && in_array($requested, $this->disabled, true)) {
                return FormatterResolution::unavailable(FormatResult::undetermined(
                    FormatUndeterminedReason::ToolMissing,
                    $requested,
                    $dialect,
                    $style,
                    'this project set `format.binaries.'.$requested.'` to false, so that backend is '
                        .'switched off — and a backend you named is never substituted. Remove the '
                        .'`--backend` option to use what is available, or set the path back to null',
                ));
            }

            if (! $named instanceof SqlFormatter) {
                return FormatterResolution::unavailable(FormatResult::undetermined(
                    FormatUndeterminedReason::ToolMissing,
                    $requested,
                    $dialect,
                    $style,
                    'no formatter backend is registered under that name; available: '
                        .implode(', ', array_map(static fn (SqlFormatter $f): string => $f->name(), $this->formatters)),
                ));
            }

            // Named and unable to answer for this dialect is a REFUSAL, not a fallback. Substituting
            // silently would produce output the project did not ask for, and the next machine would
            // rewrite every file.
            if (! $named->isAvailable()) {
                // A NAMED backend that cannot run is still a refusal rather than a fallback — but it
                // is now discovered HERE, once, rather than by every file failing in turn. The
                // difference matters to a reader: one line saying the binary is missing, instead of
                // a hundred saying each file could not be formatted.
                return FormatterResolution::unavailable(FormatResult::undetermined(
                    FormatUndeterminedReason::ToolMissing,
                    $named->name(),
                    $dialect,
                    $style,
                    'the backend you named is not installed on this machine, and nothing is '
                        .'substituted for a backend you named — set the backend to `auto` if a '
                        .'fallback is what you want',
                ));
            }

            return $named->supports($dialect)
                ? FormatterResolution::of($named)
                : FormatterResolution::unavailable(FormatResult::undetermined(
                    FormatUndeterminedReason::DialectUnsupported,
                    $named->name(),
                    $dialect,
                    $style,
                    'the backend you named does not handle this dialect, and nothing is substituted '
                        .'for a backend you named — set the backend to `auto` if a fallback is what you want',
                ));
        }

        // What `auto` WANTED and could not have. Collected rather than discarded: falling back to
        // the built-in core is the right behavior and a silent one is not — a project on a machine
        // without pgFormatter is formatting with something else than the machine that has it, and
        // until this list existed nothing in the run said so. Strict tool mode turns it into a
        // failure; an ordinary run states it and carries on.
        $passedOver = [];

        // The first backend that is installed and handles the dialect but cannot express the style.
        // Kept rather than returned: something further down may express it. Used only when nothing
        // does, so the run still reports the option by name instead of refusing to pick at all.
        $fallback = null;

        foreach (self::AUTO_ORDER as $name) {
            $candidate = $this->byName($name);

            if (! $candidate instanceof SqlFormatter || ! $candidate->supports($dialect)) {
                continue;
            }

            // The style, as well as dialect and machine. Without it `auto` would pick pgFormatter for
            // a project with `leading_commas`, and every file would come back
            // `format_style_not_expressible` while the core, which does leading commas, sat further
            // down the list.
            $expresses = $candidate->unexpressible($style) === [];

            // Availability as well as dialect support, and the second half is what `auto` means.
            // Without it the best backend for the dialect is chosen whether or not it is installed,
            // and every file comes back `format_tool_missing` while the core that would have worked
            // sits one line down the list. Measured, on a machine without pgFormatter.
            if ($candidate->isAvailable()) {
                if ($expresses) {
                    return FormatterResolution::of($candidate, $passedOver);
                }

                $fallback ??= $candidate;

                continue;
            }

            // Missing, and able to express this style: the one case worth naming. A backend that
            // could not have served the project's style is no loss, whether or not it is installed,
            // and strict tool mode must not fail a build over it.
            if ($expresses) {
                $passedOver[] = $name;
            }
        }

        if ($fallback instanceof SqlFormatter) {
            return FormatterResolution::of($fallback, $passedOver);
        }

        // Unreachable while the built-in core is registered, and NOT written as an assumption: a
        // project can register its own set, and a resolver that returned null here would hand a
        // null to a caller that has no way to describe what happened.
        return FormatterResolution::unavailable(FormatResult::undetermined(
            FormatUndeterminedReason::ToolMissing,
            'auto',
            $dialect,
            $style,
            'no registered backend handles this dialect',
        ));
    }

    private function byName(string $name): ?SqlFormatter
    {
        foreach ($this->formatters as $formatter) {
            if ($formatter->name() === $name) {
                return $formatter;
            }
        }

        return null;
    }
}
