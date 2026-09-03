<?php

declare(strict_types=1);

namespace Pushery\SQLens\Api;

/**
 * One difference between two API surfaces, classified and explained.
 *
 * ## Why every change carries a REMEDY and not just a verdict
 *
 * A gate that says "this is forbidden without a major" leaves a maintainer with two options: cut a
 * major release, or delete the gate. Neither is what the promise wants, and the second is what
 * actually happens under time pressure.
 *
 * There is almost always a third option — rename becomes deprecate-plus-new-id, a severity raise
 * becomes a severity raise WITH a changelog callout — and the message is where it belongs, because
 * a maintainer reading a red build is exactly the person who needs it and exactly the moment they
 * have no patience to go looking.
 */
final readonly class SurfaceChange
{
    public function __construct(
        public SurfaceChangeClass $class,
        /** What moved — a rule id, or a contract-level key like `exit_codes`. */
        public string $subject,
        /** Which field of it, or `''` when the subject itself appeared or disappeared. */
        public string $field,
        public string $description,
        /** What to do instead, when the class forbids it. Empty when nothing is owed. */
        public string $remedy = '',
    ) {}

    /** A one-line rendering for a failing gate. */
    public function describe(): string
    {
        return $this->remedy === ''
            ? sprintf('[%s] %s', $this->class->value, $this->description)
            : sprintf('[%s] %s — %s', $this->class->value, $this->description, $this->remedy);
    }
}
