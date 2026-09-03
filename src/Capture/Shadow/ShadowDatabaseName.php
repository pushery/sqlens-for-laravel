<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Builds the name of a throwaway shadow database — `<prefix><timestamp>_<random>`,
 * restricted to `[a-z0-9_]` and never longer than PostgreSQL's 63-byte identifier
 * limit.
 *
 * The formatting is a PURE function of its inputs, kept apart from the entropy that
 * feeds it (`generate()` supplies a UTC timestamp and random bytes), so the shape,
 * the character set, and the truncation can all be asserted deterministically while
 * the produced name is still unique per run. The timestamp is inherently a wall
 * clock — that is fine, because a shadow database name never reaches a finding, so
 * it cannot affect rule-output determinism; it exists only to make a leaked
 * database traceable to the run that made it.
 *
 * Truncation is deterministic and preserves uniqueness: the unique suffix
 * (timestamp + random) is kept whole, and only the prefix is trimmed to fit. A
 * pathologically long prefix is cut from the left of the whole, never a random
 * slice — the same input always yields the same name.
 *
 * The length limit is a parameter because it differs per engine: PostgreSQL caps
 * an identifier at 63 bytes (the default), MySQL at 64. The default is the tighter
 * of the two, so a name built for one engine is always legal on the other.
 */
final class ShadowDatabaseName
{
    /**
     * The segment that marks a name as the TEMPLATE rather than the clone.
     *
     * It lives here because both halves of the scheme need it and they had already drifted: the
     * captor factory spelled `tmpl_` as a literal when building the name, and the parser below
     * assumed the timestamp came immediately after the prefix. So the factory produced names the
     * parser could not read — which meant the orphan sweep, which ages a database by the timestamp
     * in its name, could never age a template and therefore never removed one. It collected leaked
     * clones and left leaked TEMPLATES, which carry the project's whole schema.
     */
    public const string TEMPLATE_SEGMENT = 'tmpl_';

    /** PostgreSQL's identifier length limit, in bytes — the tighter default. */
    private const int DEFAULT_MAX_LENGTH = 63;

    /** The width of the random token, in hex characters (4 bytes → 8 hex chars). */
    private const int RANDOM_BYTES = 4;

    /**
     * A fresh, unique shadow database name for the given prefix, stamped with the
     * current UTC time and a random token, within the engine's identifier limit.
     */
    public static function generate(string $prefix, int $maxLength = self::DEFAULT_MAX_LENGTH): string
    {
        $timestamp = new DateTimeImmutable('now', new DateTimeZone('UTC'))->format('YmdHis');

        return self::format($prefix, $timestamp, bin2hex(random_bytes(self::RANDOM_BYTES)), $maxLength);
    }

    /**
     * Assemble and normalize a shadow database name from its parts. Pure: the same
     * prefix, timestamp, random token, and limit always produce the same name.
     */
    public static function format(string $prefix, string $timestamp, string $random, int $maxLength = self::DEFAULT_MAX_LENGTH): string
    {
        $prefix = self::sanitize($prefix);
        $suffix = self::sanitize($timestamp).'_'.self::sanitize($random);

        // Keep the unique suffix whole and trim only the prefix to fit the limit, so
        // two runs a moment apart still differ. If the suffix alone already exceeds
        // the limit (a pathological timestamp/token), fall back to a deterministic
        // left-cut of the suffix and drop the prefix entirely.
        $budget = $maxLength - strlen($suffix);

        if ($budget < 0) {
            return substr($suffix, 0, $maxLength);
        }

        return substr($prefix, 0, $budget).$suffix;
    }

    /** The prefix a TEMPLATE database is named from, given the run's shadow prefix. */
    public static function templatePrefix(string $prefix): string
    {
        return $prefix.self::TEMPLATE_SEGMENT;
    }

    /**
     * The UTC time embedded in a shadow database name, or null if the name is not
     * one this scheme produced.
     *
     * The orphan sweep ages a database by the timestamp in its NAME, not by any
     * server creation-time metadata, so a name that does not match
     * `<prefix>[tmpl_]<YmdHis>_…` returns null and is never aged — and therefore never
     * dropped by the sweep. A database carrying the prefix but not the format is left
     * alone rather than guessed about.
     *
     * THE TEMPLATE SEGMENT IS SPELLED OUT, not matched as "any word before the digits",
     * and that is the whole difference between a fix and a loosening. The promise this
     * method carries is that a database wearing our prefix but not our scheme is out of
     * the sweep's reach — somebody's own `sqlens_shadow_backup_…` has to stay untouched.
     * A pattern permissive enough to catch `tmpl_` generically would catch that too, and
     * the sweep DROPS what it ages.
     */
    public static function timestampOf(string $name, string $prefix): ?DateTimeImmutable
    {
        $prefix = self::sanitize($prefix);

        if (! str_starts_with($name, $prefix)) {
            return null;
        }

        $rest = substr($name, strlen($prefix));

        // The one segment this scheme inserts, and only when it is there. Stripped before the
        // timestamp is read, so both halves of a run age the same way.
        if (str_starts_with($rest, self::TEMPLATE_SEGMENT)) {
            $rest = substr($rest, strlen(self::TEMPLATE_SEGMENT));
        }

        if (preg_match('/^(\d{14})_/', $rest, $matches) !== 1) {
            return null;
        }

        $timestamp = DateTimeImmutable::createFromFormat('!YmdHis', $matches[1], new DateTimeZone('UTC'));

        return $timestamp === false ? null : $timestamp;
    }

    /** Lower-case and strip everything outside `[a-z0-9_]`. */
    private static function sanitize(string $value): string
    {
        return (string) preg_replace('/[^a-z0-9_]/', '', strtolower($value));
    }
}
