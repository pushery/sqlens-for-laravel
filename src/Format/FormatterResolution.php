<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Pushery\SQLens\Contracts\SqlFormatter;

/**
 * Which backend will format, or the finished refusal to hand back instead.
 *
 * Two states rather than a nullable formatter, for the reason the deploy layer states everywhere: a
 * caller handed a null has to invent the explanation, and the explanation is the valuable half. Here
 * the refusal arrives already shaped as a {@see FormatResult}, so a command can report it through
 * exactly the path a formatting failure takes.
 *
 * ONE non-nullable field rather than two nullable ones, and the difference is not cosmetic. Two
 * nullables describe four states where the class has two, so a caller who has ruled out the refusal
 * still holds a `?SqlFormatter` and has to write a branch for the pair that cannot occur — a branch
 * no run can enter, which the 100% floor then reports as an uncovered line for as long as it exists.
 * A union type rules the impossible pair out at the type level instead, and the caller's `instanceof`
 * narrows all the way in one step.
 */
final readonly class FormatterResolution
{
    /**
     * @param  list<string>  $passedOver  backends `auto` would have PREFERRED and could not use,
     *                                    because they are not installed on this machine
     */
    private function __construct(public SqlFormatter|FormatResult $outcome, public array $passedOver = []) {}

    /** @param list<string> $passedOver */
    public static function of(SqlFormatter $formatter, array $passedOver = []): self
    {
        return new self($formatter, $passedOver);
    }

    public static function unavailable(FormatResult $refusal): self
    {
        return new self($refusal);
    }
}
