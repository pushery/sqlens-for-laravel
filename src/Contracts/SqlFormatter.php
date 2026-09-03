<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Format\Dialect;
use Pushery\SQLens\Format\FormatResult;
use Pushery\SQLens\Format\FormatStyle;

/**
 * The seam behind which a pure-PHP core, pgFormatter and SQLFluff are interchangeable.
 *
 * Three methods, and the smallness is the design: a backend that needed a fourth would be one this
 * package had to know something specific about, and the point of the seam is that it does not.
 *
 * ## `format()` NEVER throws
 *
 * Every failure a formatter can meet — a missing binary, a version outside the measured window, a
 * timeout, an unparsable statement, a style option it cannot express — is an ordinary event on a
 * real machine, and each comes back as {@see FormatResult::undetermined()} with a named reason. A
 * suite formatting a hundred files must be able to report the two it could not.
 *
 * That is also why there is no `formatOrFail()`. An alternative that throws is an alternative
 * somebody reaches for, and the first `catch` written around it turns a named reason into a
 * sentence.
 */
interface SqlFormatter
{
    /**
     * The name this backend is reported under — stable, lowercase, and part of the public surface.
     *
     * It appears in every result and in every report, so a project can see which backend produced
     * the file in front of them. Renaming one is a breaking change to a report consumers parse.
     */
    public function name(): string;

    /**
     * Whether this backend handles that dialect at all.
     *
     * Asked SEPARATELY from formatting so a resolver can pick a backend without running one — and so
     * "this backend does not do MySQL" is a fact available before a file is read, rather than a
     * refusal discovered per statement.
     */
    public function supports(Dialect $dialect): bool;

    /**
     * Whether this backend can actually run right now.
     *
     * SEPARATE from `supports()`, and the separation is the whole reason this method exists.
     * `supports()` is about the DIALECT — a property of the backend that never changes — and this is
     * about the MACHINE: is the binary installed, is it executable, is its version one this adapter
     * was measured against.
     *
     * ⚠️ Without it, `auto` picks the best backend for the dialect and discovers per file that it
     * cannot run — so every file comes back undetermined and the run reports a tree it never looked
     * at. Measured: with pgFormatter uninstalled, `auto` chose it anyway and reported ten files as
     * `format_tool_missing` instead of formatting them with the core that was right there.
     *
     * It is asked ONCE per resolution rather than per file, because locating a binary is a syscall
     * and the answer cannot change during a run.
     */
    public function isAvailable(): bool;

    /** Format one statement, or say why not. Never throws. */
    public function format(string $sql, Dialect $dialect, FormatStyle $style): FormatResult;
}
