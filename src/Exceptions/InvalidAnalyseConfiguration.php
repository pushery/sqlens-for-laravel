<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The analyse suite was configured with something it cannot act on.
 *
 * A USER misconfiguration, unlike most of this namespace, and that is why it throws instead of
 * degrading. The alternative — fall back to the default and carry on — is the exact failure this
 * package refuses everywhere else: a project writes `policy: documentd`, the run is green, and
 * nobody learns that the setting never applied. A rule silently switched on is annoying; a rule
 * silently switched OFF is a safety promise the project believes it has and does not.
 *
 * PHPStan surfaces a throw from a service constructor with its message, so the sentence a
 * developer reads here is the one written below.
 */
final class InvalidAnalyseConfiguration extends RuntimeException
{
    /**
     * `policy` names a mode that does not exist.
     *
     * @param  list<string>  $accepted
     */
    public static function unknownPolicy(string $given, array $accepted): self
    {
        return new self(sprintf(
            'sqlens.analyse.policy is "%s", which is not a mode this package has. Accepted: %s. '
            .'Falling back to the default would leave the justification duty in a state nobody chose.',
            $given,
            implode(', ', $accepted),
        ));
    }

    /**
     * `policy` arrived as boolean true — NEON's `on` or `yes`.
     *
     * The mirror image of the `off` case, and the one that must NOT be guessed. `false` has exactly
     * one plausible reading (the mode called `off`); `true` has two (`documented` and `strict`) and
     * picking either would leave a project under a duty it did not choose.
     *
     * @param  list<string>  $accepted
     */
    public static function booleanPolicy(array $accepted): self
    {
        return new self(sprintf(
            'sqlens.analyse.policy is on/yes, which NEON reads as boolean true. That names no mode: '
            .'"documented" and "strict" are both "on", and choosing one for you would set a duty you '
            .'did not pick. Write one of: %s.',
            implode(', ', $accepted),
        ));
    }

    /** An `exclude_paths` entry points at nothing. */
    public static function missingExcludePath(string $path): self
    {
        return new self(sprintf(
            'sqlens.analyse.exclude_paths lists "%s", which does not exist. A path that matches no '
            .'file excludes nothing, so the exemption a project believes it has would silently not '
            .'apply — most often a typo or a directory that moved.',
            $path,
        ));
    }

    /** A `justification_placeholders` entry is blank. */
    public static function blankPlaceholder(): self
    {
        return new self(
            'sqlens.analyse.justification_placeholders contains an empty entry. An empty reason is '
            .'already refused in every mode, so the entry would match nothing and read as if it did.',
        );
    }
}
