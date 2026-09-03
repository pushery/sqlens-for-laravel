<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server running with `standard_conforming_strings = off`.
 *
 * ## What actually goes wrong
 *
 * With it off, a backslash inside an ordinary single-quoted literal is an escape character rather
 * than a backslash. `'a\nb'` stops being three characters and a backslash and becomes `a`, a
 * newline, `b`; `'C:\temp'` loses its tab. Nothing errors — the literal simply means something else
 * than the person who wrote it intended, and the difference only shows up in the data.
 *
 * The reason this is worth a rule rather than a footnote is that the same migration file produces
 * different rows depending on a server setting. That breaks the package's own premise: a migration
 * reviewed on one instance and applied to another is supposed to do the same thing on both.
 *
 * ## Why `safety` and not `security`
 *
 * The setting has a well-known security dimension — it is the historical backdrop to a family of
 * escaping mistakes — and it is deliberately NOT filed under `security` here. That category carries
 * its own severity axis and its own gate, which belongs to the security suite; a level rule quietly
 * landing in it would bypass the level gate entirely. What this rule reports is a correctness
 * hazard on the level axis, and it says so.
 */
final class StandardConformingStringsOffRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L6.STANDARD_CONFORMING_STRINGS_OFF';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'standard_conforming_strings';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // PostgreSQL reports booleans as `on`/`off` here, not `true`/`1`. Compared against the
        // matrix's expectation rather than a literal in this file — the whole reason the matrix
        // exists — and case-folded because the value is a keyword, not data.
        if (strcasecmp($serverValue, $expectation->expectation ?? 'on') === 0) {
            return null;
        }

        return sprintf(
            'the server has standard_conforming_strings = %s, so a backslash inside an ordinary '.
            "single-quoted literal is an escape character: '\\\\n' is a newline rather than the two ".
            'characters written. Nothing errors — the literal simply means something other than '.
            'intended, and the same migration then produces different rows on this server than on one '.
            'with the standard behavior. %s',
            $serverValue,
            $this->remediation($expectation),
        );
    }
}
