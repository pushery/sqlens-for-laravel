<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Analyse;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use Pushery\SQLens\Canonical\Fingerprint;

/**
 * What tells two call sites in one file apart without their line number: the functions the call
 * sits in, the code on the line the analyzer reported, and, for two identical lines in one function,
 * their order.
 *
 * A call-site finding carries its file and the analyzer's identifier and nothing else that stays
 * put, so two findings of one rule in one file used to share a fingerprint, in SARIF's
 * `partialFingerprints` among other places. The line number would tell them apart and is the one
 * thing that must not: a line inserted above moves it. The function and the code move with the call.
 *
 * Read from the source the analysis read. A file that cannot be read or parsed, or a line it does
 * not have, yields no identity, and the finding keeps the fingerprint it had rather than one
 * computed from something else.
 */
final class CallsiteIdentity
{
    /** @var array<string, array{lines: list<string>, scopes: list<array{int, int, string}>}|null> */
    private array $files = [];

    /**
     * @param  string  $file  the readable path of the analyzed file
     * @param  int  $line  the line the analyzer reported, counted from 1
     */
    public function at(string $file, int $line): ?Fingerprint
    {
        // Read once per file and run, a file that could not be read included.
        if (! array_key_exists($file, $this->files)) {
            $this->files[$file] = $this->read($file);
        }

        $read = $this->files[$file];
        $code = $read['lines'][$line - 1] ?? '';

        if ($read === null || $code === '') {
            return null;
        }

        $scope = $this->scopeOf($read['scopes'], $line);
        $twinsAbove = 0;

        for ($earlier = 1; $earlier < $line; $earlier++) {
            if ($read['lines'][$earlier - 1] === $code && $this->scopeOf($read['scopes'], $earlier) === $scope) {
                $twinsAbove++;
            }
        }

        return Fingerprint::fromValue(hash('sha256', implode("\x1f", [$scope, $code, (string) $twinsAbove])));
    }

    /**
     * Every function-like the line sits in, outermost first, named the way a reader would:
     * `Class::method`, a function's name, `{closure}` for a closure or an arrow function. A line
     * outside every function is `{main}`. The whole path rather than the innermost name, so the same
     * line in closures of two different methods is two call sites.
     *
     * @param  list<array{int, int, string}>  $scopes  ordered outermost first
     */
    private function scopeOf(array $scopes, int $line): string
    {
        $path = [];

        foreach ($scopes as [$from, $to, $name]) {
            if ($from <= $line && $line <= $to) {
                $path[] = $name;
            }
        }

        return $path === [] ? '{main}' : implode(' > ', $path);
    }

    /**
     * The file's lines with their whitespace collapsed, so an indentation change is not a new call
     * site, and the line range of every function-like in it.
     *
     * @return array{lines: list<string>, scopes: list<array{int, int, string}>}|null
     */
    private function read(string $file): ?array
    {
        $source = is_file($file) ? @file_get_contents($file) : false;

        if ($source === false) {
            return null;
        }

        try {
            $ast = new ParserFactory()->createForHostVersion()->parse($source) ?? [];
        } catch (Error) {
            return null;
        }

        $finder = new NodeFinder;
        $scopes = [];

        foreach ($finder->findInstanceOf($ast, ClassLike::class) as $class) {
            foreach ($class->getMethods() as $method) {
                $scopes[] = [
                    $method->getStartLine(),
                    $method->getEndLine(),
                    ($class->name?->toString() ?? '{class}').'::'.$method->name->toString(),
                ];
            }
        }

        $functions = $finder->find(
            $ast,
            static fn (Node $node): bool => $node instanceof Function_ || $node instanceof Closure || $node instanceof ArrowFunction,
        );

        foreach ($functions as $function) {
            $scopes[] = [
                $function->getStartLine(),
                $function->getEndLine(),
                $function instanceof Function_ ? $function->name->toString() : '{closure}',
            ];
        }

        // Outermost first: an enclosing function starts earlier, or on the same line and ends later.
        // The sort is stable, so two that share both lines keep the order the finder met them in,
        // which is the order they are written in.
        usort($scopes, static fn (array $one, array $other): int => [$one[0], $other[1]] <=> [$other[0], $one[1]]);

        return [
            'lines' => array_map(
                static fn (string $line): string => trim((string) preg_replace('/\s+/', ' ', $line)),
                explode("\n", $source),
            ),
            'scopes' => $scopes,
        ];
    }
}
