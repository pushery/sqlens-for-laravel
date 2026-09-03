<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Subjects\MigrationDirection;

/**
 * Which section of a run produced a statement.
 *
 * A roundtrip runs `up`, then `down`, then `up` again — and the second `up` is
 * NOT the first one repeated: it runs against a schema the `down` just touched,
 * so it can legitimately differ. Collapsing both onto `MigrationDirection::Up`
 * would make a roundtrip divergence invisible, which is the one thing the
 * roundtrip exists to surface.
 *
 * So direction (what the migration method is) and section (where in the run it
 * ran) are separate axes. The backed values reach the JSON output.
 */
enum CaptureSection: string
{
    case Up = 'up';
    case Down = 'down';
    case UpAgain = 'up_again';

    /** The migration method this section runs — the second `up` is still an `up`. */
    public function direction(): MigrationDirection
    {
        return match ($this) {
            self::Up, self::UpAgain => MigrationDirection::Up,
            self::Down => MigrationDirection::Down,
        };
    }

    /** A one-line English label for reports. */
    public function label(): string
    {
        return match ($this) {
            self::Up => 'up',
            self::Down => 'down',
            self::UpAgain => 'up (after down, roundtrip)',
        };
    }
}
