<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

/**
 * Matches a repo-relative path against a glob, the same way on every platform.
 *
 * Written out rather than delegated to fnmatch(): that function's behavior varies
 * by platform (and is absent on some), which would make an ignore rule suppress a
 * finding on a developer's machine and not in CI. A suppression that depends on
 * the operating system is worse than none, because it looks like it works.
 *
 * The rules, in full:
 *   `**`  any characters, directory separators included
 *   `*`   any characters except a directory separator
 *   `?`   exactly one character except a directory separator
 * Everything else is literal. Backslashes are folded to forward slashes on both
 * sides first, so a Windows-style path and a Unix-style glob still agree.
 */
final readonly class PathGlob
{
    public static function matches(string $glob, string $path): bool
    {
        return preg_match(self::toRegex(self::forwardSlash($glob)), self::forwardSlash($path)) === 1;
    }

    private static function toRegex(string $glob): string
    {
        $regex = '';
        $length = strlen($glob);

        for ($i = 0; $i < $length; $i++) {
            $char = $glob[$i];

            if ($char === '*' && ($glob[$i + 1] ?? '') === '*') {
                $regex .= '.*';
                $i++;

                continue;
            }

            $regex .= match ($char) {
                '*' => '[^/]*',
                '?' => '[^/]',
                default => preg_quote($char, '#'),
            };
        }

        return '#^'.$regex.'$#';
    }

    private static function forwardSlash(string $value): string
    {
        return str_replace('\\', '/', $value);
    }
}
