<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A file this package SHIPS could not be read, or is not the shape this build implements.
 *
 * ## One policy for every shipped register
 *
 * Every bundled register in this tree refuses a broken artifact by name —
 * {@see UnreadableBaseline}, {@see UnreadableSarifSchema}, {@see UnreadableDriftExcludes}, the
 * dictionaries beside them, and this one. None returns an empty base set, which is the one answer a
 * loader must never give, because empty is not "cannot read" — it is a confident statement that
 * there is nothing to know.
 *
 * **What an empty answer would cost.** `MysqlAdminPrivileges::judged()` is the vocabulary two
 * security rules judge a server against, and both of them open with "if the list is empty, return
 * no findings". An unreadable artifact read as empty would turn `SEC.PRIV.GRANT_ADMIN*` into a pass
 * on every server on earth — not an `undetermined`, a pass — and the rule would go on looking
 * healthy. A check that the file is present, run in the package's own repository, protects no
 * installation.
 *
 * ## Why it is thrown from the shipped path and not from every reader
 *
 * `fromFile()` on these classes is a test seam, and deliberately so: a suite has to be able to put an
 * artifact into states the shipped one is never in — absent, truncated, a row without an id. Those
 * calls pass a path they chose and want the tolerant answer. The shipped path chose no path; if the
 * file it names is unreadable the installation is broken, and that is worth a crash rather than a
 * silent pass. So the strictness sits where the artifact is not a parameter.
 */
final class UnreadableShippedArtifact extends RuntimeException
{
    public function __construct(string $path, string $why)
    {
        parent::__construct(sprintf(
            'The shipped artifact at %s cannot be used: %s. It is refused rather than treated as empty — '
            .'an empty register would make the rules that read it silently correct about every server, '
            .'which is a pass and not an undetermined. Reinstall the package.',
            $path,
            $why,
        ));
    }
}
