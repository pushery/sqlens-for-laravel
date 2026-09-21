<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A file this package SHIPS could not be read, or is not the shape this build implements.
 *
 * ## One policy, because three loaders had the other one
 *
 * Seven bundled registers in this tree already refuse a broken artifact by name —
 * {@see UnreadableBaseline}, {@see UnreadableSarifSchema}, {@see UnreadableDriftExcludes} and the
 * dictionaries beside them. Three did not: they returned an EMPTY base set, which is the one answer a
 * loader must never give, because empty is not "cannot read" — it is a confident statement that
 * there is nothing to know.
 *
 * ⚠️ **What the empty answer cost, in the worst of the three.** `MysqlAdminPrivileges::judged()` is
 * the vocabulary two security rules judge a server against, and both of them open with "if the list
 * is empty, return no findings". An unreadable artifact therefore turned `SEC.PRIV.GRANT_ADMIN*` into
 * a PASS on every server on earth — not an `undetermined`, a pass. The rule went on looking healthy,
 * and so did every test about it.
 *
 * ⚠️ **And the reasoning that defended it pointed at a guard the consumer does not have.** Its own
 * docblock argued that "the loudest honest answer available here is no entries plus a shipped guard
 * that proves the file is present" — but that guard lives under `tests/`, which is RELEASE_STRIP and
 * reaches no `vendor/` tree. The belt existed only in the repository that did not need it.
 *
 * ## Why it is thrown from the SHIPPED path and not from every reader
 *
 * `fromFile()` on these classes is a test seam, and deliberately so: a suite has to be able to put an
 * artifact into states the shipped one is never in — absent, truncated, a row without an id. Those
 * calls pass a path they chose and want the tolerant answer. The shipped path chose no path; if the
 * file it names is unreadable the INSTALLATION is broken, and that is worth a crash rather than a
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
