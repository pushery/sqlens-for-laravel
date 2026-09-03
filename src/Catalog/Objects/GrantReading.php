<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;

/**
 * The three-valued answer to "who may do what on this server".
 *
 * The empty case is the dangerous one, and it is the reason this is not a bare list. On MySQL an
 * account without `SELECT ON mysql.*` gets a refusal from the grant tables — and
 * `information_schema.SCHEMA_PRIVILEGES`, the obvious substitute, does not refuse at all: it narrows
 * silently to what the caller may see. Both roads lead to "no grants found", and only one of them
 * means it.
 *
 * So a reading that could not see everything says `partial` and carries the skips that explain it,
 * and a consumer cannot reach the grants without having been handed that caveat.
 */
final readonly class GrantReading
{
    /**
     * @param  list<GrantObject>  $grants  sorted by object then grantee
     * @param  list<CatalogSkip>  $skips
     */
    private function __construct(
        public array $grants,
        public CatalogCompleteness $completeness,
        public array $skips,
    ) {}

    /**
     * @param  list<GrantObject>  $grants
     */
    public static function complete(array $grants): self
    {
        return new self(self::sorted($grants), CatalogCompleteness::Complete, []);
    }

    /**
     * @param  list<GrantObject>  $grants
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function partial(array $grants, array $skips): self
    {
        return new self(self::sorted($grants), CatalogCompleteness::Partial, $skips);
    }

    public function isComplete(): bool
    {
        return $this->completeness === CatalogCompleteness::Complete;
    }

    /**
     * Everything granted to PUBLIC — the subset most security rules start from, because it reaches
     * every role that will ever exist on the server.
     *
     * @return list<GrantObject>
     */
    public function toPublic(): array
    {
        return array_values(array_filter($this->grants, static fn (GrantObject $grant): bool => $grant->isToPublic()));
    }

    /**
     * The grants somebody in this project actually made — everything a rule may judge.
     *
     * Beside {@see self::toPublic()} rather than folded into it, because the two questions are
     * different and a rule usually wants both: "does PUBLIC hold this" and "did we do that".
     *
     * @return list<GrantObject>
     */
    public function judgeable(): array
    {
        return array_values(array_filter($this->grants, static fn (GrantObject $grant): bool => $grant->isJudgeable()));
    }

    /**
     * Every grant to one grantee, by exact name.
     *
     * Exact rather than pattern-matched: on MySQL a grantee is an account with a host, and matching
     * `app` against `'app'@'10.0.%'` would answer a question about a different account.
     *
     * @return list<GrantObject>
     */
    public function to(string $grantee): array
    {
        return array_values(array_filter($this->grants, static fn (GrantObject $grant): bool => $grant->grantee === $grantee));
    }

    /**
     * @param  list<GrantObject>  $grants
     * @return list<GrantObject>
     */
    private static function sorted(array $grants): array
    {
        usort($grants, static fn (GrantObject $a, GrantObject $b): int => $a->sortKey() <=> $b->sortKey());

        return $grants;
    }
}
