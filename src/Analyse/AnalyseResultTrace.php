<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

/**
 * The proof, inside a PHPStan result, that this package's extension wrote it.
 *
 * ## Why a result needs one
 *
 * PHPStan loads an extension only when a configuration names it. A run whose configuration forgot
 * `extension.neon` finishes, exits clean and writes a JSON document without a single SQLens
 * diagnostic, which is exactly the document a run over a codebase with no raw SQL writes. Read as
 * the second, the first reports the injection half as examined when nobody examined anything.
 *
 * So the result the security suite reads comes from `--error-format=sqlens`, an error format the
 * extension registers. A PHPStan that did not load the extension has no such format and refuses to
 * start, so the document cannot exist without it. The format writes PHPStan's own JSON result and,
 * under {@see self::KEY}, the part only it can know: the errors PHPStan hit INSIDE the analysis. An
 * internal error means a file was not analyzed to the end, and its raw SQL was examined by nobody.
 *
 * This class holds the contract both sides read, the writer inside PHPStan and the reader in the
 * security suite, and loads nothing of PHPStan's: the reader runs in the application, where opening
 * PHPStan's archive to read two constants would cost more than the constants are worth.
 */
final readonly class AnalyseResultTrace
{
    /** The name PHPStan knows the format by: `--error-format=sqlens`. */
    public const string FORMAT = 'sqlens';

    /** The key the trace sits under, beside PHPStan's own `totals`, `files` and `errors`. */
    public const string KEY = 'sqlens';

    /** The shape of what sits under the key. A reader refuses a shape it does not know. */
    public const int VERSION = 1;
}
