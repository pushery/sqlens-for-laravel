<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Contracts\Subject;

/**
 * The subject for a raw-SQL callsite in PHP, reserved for the rule engine and built by
 * nothing in this package.
 *
 * The analyse suite and its injection rules do not use it. They read PHPStan's own
 * nodes through the collectors under `Analyse` and carry their signal as the data of
 * those collectors, so a rule written against this subject is handed none. The type
 * stays because it is public surface: whether it gains a producer or is withdrawn is
 * still open.
 *
 * It makes the honesty boundary "syntactic patterns, not taint analysis" visible
 * in the type: the parametrization signal is a three-valued syntactic OBSERVATION
 * (parametrized / interpolated / undetermined), not a safe/unsafe verdict. A
 * fragment of unknown origin is undetermined, never silently parametrized.
 *
 * There are deliberately no data-flow fields — taint analysis is a sealed rabbit
 * hole. The VO knows nothing about PHPStan.
 */
final readonly class RawSql implements Subject
{
    public function __construct(
        public string $file,
        public int $line,
        public string $method,
        public string $fragment,
        public ParametrizationSignal $signal,
        public FragmentOrigin $origin,
        private SubjectContext $context,
    ) {}

    public function kind(): SubjectKind
    {
        return SubjectKind::RawSql;
    }

    public function identity(): string
    {
        return $this->file.':'.$this->line.':'.$this->method;
    }

    public function context(): SubjectContext
    {
        return $this->context;
    }
}
