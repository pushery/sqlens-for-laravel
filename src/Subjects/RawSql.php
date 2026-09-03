<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Contracts\Subject;

/**
 * The subject for a raw-SQL callsite in PHP — the input of the analyse suite and
 * the injection rules.
 *
 * It makes the honesty boundary "syntactic patterns, not taint analysis" visible
 * in the type: the parametrization signal is a three-valued syntactic OBSERVATION
 * (parametrized / interpolated / undetermined), NOT a safe/unsafe verdict. A
 * fragment of unknown origin is undetermined, never silently parametrized.
 *
 * There are deliberately no data-flow fields — taint analysis is a sealed rabbit
 * hole. The VO knows nothing about PHPStan; that coupling lives in Analyse\PhpStan
 * and is built later.
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
