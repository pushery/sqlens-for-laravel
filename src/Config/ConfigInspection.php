<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * What one walk of the `sqlens` config found: the things that stop the run, and the things a
 * reader should know about but that stop nothing.
 *
 * ## Why separate lists and not one with a severity flag
 *
 * They are consumed by different code with different consequences. A violation maps to
 * `ExitCode::Misconfiguration` before a single check runs; a notice is printed and the run
 * continues on the shipped default. A single list with a flag makes it possible to forget the
 * flag at exactly one call site, and that call site would either abort on a notice or swallow a
 * violation — both silently, both only in the field.
 *
 * The third list, retired keys, is separate for the same reason and one more: its entries are SET,
 * while every notice is ABSENT. Both are printed and neither stops the run, but under the notices'
 * header a retired key would be told to re-add itself — the opposite of what its reader must do.
 *
 * ## Why the walk happens once
 *
 * {@see ConfigValidator::validate()} is the older, narrower door and still answers with the fatal
 * list alone. It delegates here rather than walking a second time: a second walk is a second
 * definition of what the schema means, and the two would agree for a long while before disagreeing
 * once, quietly. That is the failure this package keeps finding in its own guards.
 */
final readonly class ConfigInspection
{
    /**
     * @param  list<ConfigViolation>  $violations  the run must not start
     * @param  list<ConfigViolation>  $notices  the run starts; the shipped default applies
     * @param  list<ConfigViolation>  $retired  the run starts; the key is ignored, because nothing reads it any more
     */
    public function __construct(public array $violations = [], public array $notices = [], public array $retired = []) {}

    public function isValid(): bool
    {
        return $this->violations === [];
    }
}
