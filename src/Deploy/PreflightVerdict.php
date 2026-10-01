<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Console\ExitCode;

/**
 * Whether a deploy proceeds, decided once over both halves of a predeploy run.
 *
 * The command turns it into an exit status and the protocol tool into its `gate`, and neither
 * decides anything of its own: two readings of one run are two chances to disagree about whether
 * the deploy goes ahead, and the one that disagreed would be the one somebody trusted.
 */
final readonly class PreflightVerdict
{
    /**
     * @param  list<string>  $waivedReasons  the reasons a waiver named and this run raised, or an
     *                                       empty list when it opened for every reason or for none
     */
    private function __construct(
        public PreflightBlocker $blocker,
        public array $waivedReasons = [],
    ) {}

    public static function of(PreflightBlocker $blocker): self
    {
        return new self($blocker);
    }

    /** @param  list<string>  $reasons */
    public static function waivedFor(array $reasons): self
    {
        return new self(PreflightBlocker::Waived, $reasons);
    }

    public function exitCode(): ExitCode
    {
        return $this->blocker->exitCode();
    }

    public function blocks(): bool
    {
        return $this->exitCode() !== ExitCode::Clean;
    }

    /** Whether a waiver is what let the deploy proceed. */
    public function waived(): bool
    {
        return $this->blocker === PreflightBlocker::Waived;
    }
}
