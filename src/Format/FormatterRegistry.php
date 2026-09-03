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

    /** @param list<SqlFormatter> $formatters */
    public function __construct(private array $formatters = []) {}

    /**
     * The backend for a request, or a named reason there is none.
     *
     * @param  string  $requested  a backend name, or `auto`
     * @param  bool  $dialectResolved  whether the dialect is KNOWN. When it is not, only a backend
     *                                 that handles both dialects may run — picking a
     *                                 dialect-specific one against a guess is how a formatter
     *                                 produces output shaped for the wrong grammar
     */
    public function resolve(string $requested, Dialect $dialect, FormatStyle $style, bool $dialectResolved = true): FormatterResolution
    {
        if ($requested !== 'auto') {
            $named = $this->byName($requested);

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

        foreach (self::AUTO_ORDER as $name) {
            $candidate = $this->byName($name);

            // With the dialect unknown, a backend that handles only one of them is out: it would be
            // formatting against a guess, and the output is committed. Only a backend that answers
            // for BOTH is safe to run blind, which is precisely what the built-in core is.
            if (! $dialectResolved && $candidate instanceof SqlFormatter
                && (! $candidate->supports(Dialect::Pgsql) || ! $candidate->supports(Dialect::Mysql))) {
                continue;
            }

            // AVAILABILITY as well as dialect support, and the second half is what `auto` means.
            // Without it the best backend for the dialect is chosen whether or not it is installed,
            // and every file comes back `format_tool_missing` while the core that would have worked
            // sits one line down the list. Measured, on a machine without pgFormatter.
            if ($candidate instanceof SqlFormatter && $candidate->supports($dialect)) {
                if ($candidate->isAvailable()) {
                    return FormatterResolution::of($candidate, $passedOver);
                }

                // Supported here and not installed — the one case worth naming. A backend that
                // cannot handle this dialect was never a candidate, and reporting it as a loss
                // would state a gap no install on this project could close.
                $passedOver[] = $name;
            }
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
