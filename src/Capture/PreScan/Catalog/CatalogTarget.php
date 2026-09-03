<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan\Catalog;

use Pushery\SQLens\Capture\PreScan\CallTarget;
use Pushery\SQLens\Exceptions\InvalidPreScanCatalog;

/**
 * One catalog line's target, parsed from its written form into something that
 * can be held against a resolved call.
 *
 * The written form is deliberately small and total — five shapes, no wildcards
 * inside a name, no regular expressions:
 *
 * - `Vendor\Package\Thing::method` — that method on that class.
 * - `*::method` — that method on ANY receiver, for the case where the receiver's
 *   type is not statically knowable (a query builder handed around in a variable).
 * - `method()` — a free function.
 * - `Vendor\Package\Thing` — any call on that class.
 * - `Vendor\Package\*` — any call on a class under that namespace.
 *
 * Static and instance calls are matched by the SAME shape on purpose. A facade
 * reached as `Notification::send(...)` and one resolved out of the container as
 * `$notification->send(...)` fire the same side effect, and a catalog that
 * distinguished them would be bypassed by the spelling rather than by the fact.
 */
final readonly class CatalogTarget
{
    private const string CLASS_PATTERN = '/^[A-Za-z_]\w*(?:\\\\[A-Za-z_]\w*)*$/';

    private const string MEMBER_PATTERN = '/^[A-Za-z_]\w*$/';

    /**
     * @param  string|null  $class  the exact class, or null for a receiver-agnostic
     *                              or function target
     * @param  string|null  $method  the method name, or null when any member matches
     * @param  string|null  $function  the free function name
     * @param  string|null  $namespacePrefix  the namespace a class must sit under
     */
    private function __construct(
        public string $raw,
        public ?string $class,
        public ?string $method,
        public ?string $function,
        public ?string $namespacePrefix,
    ) {}

    /**
     * Parse a written target. A form this grammar does not describe is a NAMED
     * error, never a silently non-matching entry: an entry that matches nothing
     * looks exactly like a surface that is not dangerous, which is the one
     * mistake a catalog must not be able to make quietly.
     */
    public static function parse(string $raw, string $origin): self
    {
        if (trim($raw) === '') {
            throw InvalidPreScanCatalog::emptyTarget($origin);
        }

        return self::tryParse($raw) ?? throw InvalidPreScanCatalog::malformedTarget($origin, trim($raw));
    }

    /**
     * The same parse, answering with null instead of throwing.
     *
     * The config validator needs to judge a user-written target WITHOUT an
     * exception: a bad key in an application's config is a collected violation
     * that names the key, never a stack trace — while a bad entry in the
     * package's own artifact is a packaging bug and does throw. One grammar, two
     * callers, no second implementation to drift.
     */
    public static function tryParse(string $raw): ?self
    {
        $written = trim($raw);

        if ($written === '') {
            return null;
        }

        if (str_ends_with($written, '()')) {
            $function = self::member(substr($written, 0, -2));

            return $function === null ? null : new self($written, null, null, $function, null);
        }

        if (str_ends_with($written, '\\*')) {
            // The separator is kept on the stored prefix, so `App\Jobs\*` matches
            // `App\Jobs\Backfill` but not the unrelated class `App\JobsReport`.
            $prefix = self::className(substr($written, 0, -2));

            return $prefix === null ? null : new self($written, null, null, null, $prefix.'\\');
        }

        if (str_contains($written, '::')) {
            [$class, $rawMethod] = explode('::', $written, 2);
            $method = self::member($rawMethod);

            if ($method === null) {
                return null;
            }

            if ($class === '*') {
                return new self($written, null, $method, null, null);
            }

            $resolved = self::className($class);

            return $resolved === null ? null : new self($written, $resolved, $method, null, null);
        }

        $resolved = self::className($written);

        return $resolved === null ? null : new self($written, $resolved, null, null, null);
    }

    /**
     * Whether the resolved call hits this target.
     *
     * A call the scanner could NOT resolve never matches here. That is not an
     * acquittal: an unresolved call is its own pre-scan hit with its own reason,
     * and letting it match a catalog entry would report the wrong cause — the
     * user would go looking for a `Notification::send` that is not in the file.
     */
    public function matches(CallTarget $target): bool
    {
        if ($target->isDynamic) {
            return false;
        }

        if ($this->function !== null) {
            return $target->targetsFunction($this->function);
        }

        if ($this->namespacePrefix !== null) {
            return $target->class !== null && str_starts_with($target->class, $this->namespacePrefix);
        }

        if ($this->class === null) {
            return $target->method === $this->method;
        }

        return $this->method === null
            ? $target->class === $this->class
            : $target->targets($this->class, $this->method);
    }

    private static function className(string $value): ?string
    {
        $name = ltrim($value, '\\');

        return preg_match(self::CLASS_PATTERN, $name) === 1 ? $name : null;
    }

    private static function member(string $value): ?string
    {
        return preg_match(self::MEMBER_PATTERN, $value) === 1 ? $value : null;
    }
}
