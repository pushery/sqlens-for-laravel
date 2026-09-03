<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * A detected server version. Parses the real, vendor-specific version strings
 * PostgreSQL 18 and MySQL 8.4 return — e.g. `18.0 (Debian 18.0-1.pgdg13+3)` or
 * `8.4.3-log` — into major/minor/patch, and compares numerically, never by
 * string.
 *
 * "No silent green": an unparsable string does NOT become a quiet 0.0.0 — it
 * yields UndeterminedReason::UnknownServerVersion. parse() returns either a
 * ServerVersion or that reason, so the caller cannot ignore the failure.
 *
 * No MariaDB special-casing: MariaDB is a non-goal; engine identity is checked
 * by the MySQL test lane. This VO parses only the target formats.
 */
final readonly class ServerVersion
{
    private function __construct(
        public int $major,
        public int $minor,
        public int $patch,
        public string $driver,
    ) {}

    /**
     * Parse a server's own version BANNER — `18.0 (Debian 18.0-1.pgdg13+3)` and its
     * many vendor variations. Returns UndeterminedReason::UnknownServerVersion when no
     * numeric version can be read at all — never a silent default.
     *
     * The scan is deliberately lenient, because the server writes this string and we
     * only get to cope with it. That tolerance is WRONG for a pin, which a human writes
     * on purpose — see {@see parsePin()}.
     */
    public static function parse(string $raw, string $driver): self|UndeterminedReason
    {
        if (preg_match('/\d+(?:\.\d+)*/', $raw, $matches) !== 1) {
            return UndeterminedReason::UnknownServerVersion;
        }

        return self::fromParts($matches[0], $driver);
    }

    /**
     * Parse an `assume_server_version` PIN, strictly: digits and dots, nothing else,
     * anchored at both ends.
     *
     * A pin is not a banner. Someone typed it deliberately to make the run
     * deterministic, so reading it loosely defeats the only thing it is for. The
     * banner scan would accept `18.x` and hand back exactly 18.0 — a value the author
     * did not write and would not recognize, quietly narrower than the "any 18" they
     * meant. A rule windowed from 18.2 then does not fire, silently and with no
     * message, which is the confidently-wrong verdict that is worse than no verdict.
     *
     * So a pin is either read exactly or refused outright, with its own named reason.
     */
    public static function parsePin(string $raw, string $driver): self|UndeterminedReason
    {
        if (preg_match('/^\d+(?:\.\d+){0,2}$/', trim($raw)) !== 1) {
            return UndeterminedReason::UnreadableServerVersionPin;
        }

        return self::fromParts(trim($raw), $driver);
    }

    /** Build a version from an already-validated `major[.minor[.patch]]` string. */
    private static function fromParts(string $numeric, string $driver): self
    {
        $parts = array_map(intval(...), explode('.', $numeric));

        return new self(
            $parts[0],
            $parts[1] ?? 0,
            $parts[2] ?? 0,
            $driver,
        );
    }

    /** Build a version directly from known numbers (for pins and tests). */
    public static function of(int $major, int $minor, int $patch, string $driver): self
    {
        return new self($major, $minor, $patch, $driver);
    }

    /**
     * The canonical `major.minor.patch` rendering — what a report, a version
     * window in the generated docs, and a run header print.
     *
     * Always all three components, never the shortest form that round-trips: a
     * window printed as `18` in one place and `18.0.0` in another is the same
     * fact in two spellings, and a reader comparing two reports would have to
     * normalize them by hand. The driver is deliberately not part of it — it is
     * its own field wherever a version is shown.
     */
    public function toString(): string
    {
        return sprintf('%d.%d.%d', $this->major, $this->minor, $this->patch);
    }

    /** Numeric comparison key: major, minor and patch each get four digits so 18.10 sorts above 18.9. */
    private function comparable(): int
    {
        return ($this->major * 1_000_000) + ($this->minor * 1_000) + $this->patch;
    }

    public function atLeast(self $other): bool
    {
        return $this->comparable() >= $other->comparable();
    }

    public function isBelow(self $other): bool
    {
        return $this->comparable() < $other->comparable();
    }
}
