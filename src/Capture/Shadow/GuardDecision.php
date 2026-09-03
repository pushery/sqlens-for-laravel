<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * The production guard's verdict: whether a database-creating run may proceed,
 * and — when it may not — the named reason it was held.
 *
 * It also carries the parameters a reader needs to reproduce the decision: the
 * environment the run saw and whether `--force` was in effect. Determinism is not
 * only about SQL; a run that a user cannot explain afterwards is not reproducible,
 * so the guard's inputs travel into the run header alongside its outcome.
 */
final readonly class GuardDecision
{
    private function __construct(
        public bool $allowed,
        public ?GuardBlockReason $blockReason,
        public string $environment,
        public bool $force,
    ) {}

    public static function allow(string $environment, bool $force): self
    {
        return new self(true, null, $environment, $force);
    }

    public static function block(GuardBlockReason $reason, string $environment, bool $force): self
    {
        return new self(false, $reason, $environment, $force);
    }

    public function isBlocked(): bool
    {
        return ! $this->allowed;
    }

    /**
     * The run-header parameters. The reporter reads these so a run explains, from
     * its own output, why the guard let it through or held it.
     *
     * @return array{mode: string, environment: string, force: bool, guard: string}
     */
    public function toArray(): array
    {
        return [
            'mode' => 'shadow',
            'environment' => $this->environment,
            'force' => $this->force,
            // 'allowed' when it passed; otherwise the specific block reason, which a
            // blocked decision always carries.
            'guard' => $this->blockReason instanceof GuardBlockReason ? $this->blockReason->value : 'allowed',
        ];
    }
}
