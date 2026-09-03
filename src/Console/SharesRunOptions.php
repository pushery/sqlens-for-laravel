<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Pushery\SQLens\Categories\CategorySelection;
use Pushery\SQLens\Exceptions\UnknownCategory;

/**
 * The options every suite command shares, resolved once so the suites cannot drift apart.
 *
 * `--level`, `--category` and `--output` mean the same thing in `sqlens:lint` and `sqlens:audit`,
 * and a user who has learned one has learned both. That is only true while there is ONE
 * implementation: two copies of "reject a level above 9" would eventually disagree about whether 10
 * is an error or a clamp, and the disagreement would be invisible because each command's own test
 * would still pass.
 *
 * Each resolver returns `false` for "already rejected, and the reason is on STDERR", so a command
 * reads as a list of guards rather than a nest of conditionals. `null` means "not given, take the
 * configured value" — a third answer that must not collapse into either of the others.
 */
trait SharesRunOptions
{
    // The output plumbing every suite command needs, whatever flags it narrows a run with. Split
    // apart because this trait's validators read `--level`, `--category` and `--min-severity`, and
    // a command that offers none of those cannot use them — see WritesReportOutput's own note.
    use ResolvesMinSeverity;
    use WritesReportOutput;

    /**
     * The cumulative strictness level, or false when the flag was given and is not one.
     *
     * Out of range is a named misconfiguration rather than a value quietly clamped: a run silently
     * moved from the 12 somebody typed to 9 is a run that answered a question nobody asked.
     */
    private function validatedLevel(): int|false|null
    {
        $level = $this->option('level');

        if (! is_string($level) || $level === '') {
            return null;
        }

        if (! ctype_digit($level) || (int) $level > 9) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.invalid_level', ['level' => $level]));

            return false;
        }

        return (int) $level;
    }

    /**
     * The categories to scope to, or false when one of them is not a category.
     *
     * A quietly dropped token would scope a run to nothing and let it read as clean — the silent
     * green this package refuses, arriving through a typo rather than through a bug.
     *
     * @return list<string>|false|null
     */
    private function validatedCategories(): array|false|null
    {
        $raw = $this->option('category');

        // Declared `--category=*`, so Symfony guarantees an array. Only emptiness distinguishes
        // "not given" from "given as nothing", and that distinction is the one this method exists
        // to preserve.
        if ($raw === []) {
            return null;
        }

        try {
            return CategorySelection::parse(array_values(array_filter($raw, is_string(...))))->values();
        } catch (UnknownCategory $exception) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.unknown_category', [
                'category' => $exception->requested,
                'available' => implode(', ', UnknownCategory::available()),
            ]));

            return false;
        }
    }
}
