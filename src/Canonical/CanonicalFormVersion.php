<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * The canonical form is a versioned contract, not an implementation detail —
 * kin to the baseline / debt-ledger formats. The version travels with every
 * canonical statement so the later drift comparator can interpret
 * comparisons across time, and so an artifact produced by an unknown version is
 * a named undetermined case rather than a silently mis-read string.
 */
final readonly class CanonicalFormVersion
{
    /**
     * The version this build of the canonicalizer produces. Bumps on ANY change to the canonical
     * form — including one that only adds a keyword.
     *
     * The "only a keyword" exemption was considered and rejected, and the reason is what the
     * version is FOR. A consumer comparing two artifacts sees bytes, not causes: it cannot tell a
     * new normalization stage from a keyword list that grew, only that the same input now produces
     * a different string. A version that exempted the second kind would therefore mean "comparable"
     * while the artifacts are not — which is the single question it exists to answer.
     *
     * Bumping is cheap by construction: {@see self::isKnown()} accepts every version up to CURRENT,
     * so older artifacts stay readable. A number that moves often and means something is worth more
     * than one that stays at 1 and means nothing.
     *
     * Went to 2 for the three keyword extensions that had already changed the form without saying
     * so — once, not once per extension: the point is that the CURRENT form differs from form 1,
     * not how many commits it took to get there.
     *
     * Went to 3 for `SCHEMA`, added to the PostgreSQL list so `DROP SCHEMA` could match a signature
     * and reach a rule. It is the fourth keyword extension and the first to arrive with its bump
     * attached — the paragraph above describes the other three, which is a warning this one nearly
     * repeated. Measured before and after, and the drift is not theoretical:
     *
     *     alter table "users" add column schema varchar(255)
     *       form 2 -> ALTER TABLE users ADD COLUMN schema VARCHAR(255)
     *       form 3 -> ALTER TABLE users ADD COLUMN SCHEMA VARCHAR(255)
     *
     *     create table "schema" (id bigint)
     *       form 2 -> CREATE TABLE schema (id BIGINT)
     *       form 3 -> CREATE TABLE "schema" (id BIGINT)
     *
     * Both are more correct — an identifier colliding with a keyword keeps its quotes, which is
     * what makes it unambiguous — and both change the STRING, which is all a fingerprint compares.
     * A project with a column named `schema` would otherwise have seen its ledger report drift that
     * nothing in its own tree caused.
     */
    public const int CURRENT = 3;

    public function __construct(public int $version) {}

    public static function current(): self
    {
        return new self(self::CURRENT);
    }

    /** Whether this version is one this build knows how to read — an unknown version is undetermined, never guessed. */
    public function isKnown(): bool
    {
        return $this->version >= 1 && $this->version <= self::CURRENT;
    }

    public function equals(self $other): bool
    {
        return $this->version === $other->version;
    }
}
