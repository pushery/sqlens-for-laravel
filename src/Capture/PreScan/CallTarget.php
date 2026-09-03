<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

/**
 * What a call in a migration actually points at, once imports and aliases are
 * resolved — or an explicit statement that it could not be resolved.
 *
 * The unresolvable case is a FIRST-CLASS value, not a null. A dynamic class name,
 * `call_user_func`, or a variable method name means the scanner genuinely does
 * not know what runs; returning null would let every caller quietly treat "I
 * could not tell" as "nothing dangerous here". The pre-scan is deliberately
 * conservative — unresolved is a hit, never an acquittal — and that only works if
 * the type makes the state impossible to overlook.
 */
final readonly class CallTarget
{
    private function __construct(
        public ?string $class,
        public ?string $method,
        public ?string $function,
        public bool $isDynamic,
        public string $description,
    ) {}

    /** `Http::get(...)` — a static call whose class resolved to an FQCN. */
    public static function staticCall(string $class, string $method): self
    {
        return new self($class, $method, null, false, $class.'::'.$method);
    }

    /**
     * `$importer->handle(...)` or `(new Importer)->run()` — an instance call. The
     * class is nullable because a call on a variable of unknown type resolves its
     * method name but not its receiver.
     */
    public static function instanceCall(?string $class, string $method): self
    {
        return new self($class, $method, null, false, ($class ?? '?').'->'.$method);
    }

    /** A free function call — `dispatch(...)`, `event(...)`, a project helper. */
    public static function function(string $function): self
    {
        return new self(null, null, $function, false, $function.'()');
    }

    /**
     * The scanner could not determine what this call runs. The description says
     * WHAT was unresolvable, so the resulting finding can name it instead of
     * reporting a bare "something dynamic".
     */
    public static function dynamic(string $description): self
    {
        return new self(null, null, null, true, $description);
    }

    /** Whether this call targets the given fully-qualified class, exactly. */
    public function targetsClass(string $fqcn): bool
    {
        return $this->class === ltrim($fqcn, '\\');
    }

    /** Whether this is `<class>::<method>` / `<class>-><method>` for the given pair. */
    public function targets(string $fqcn, string $method): bool
    {
        return $this->targetsClass($fqcn) && $this->method === $method;
    }

    /** Whether this is a call to the given free function. */
    public function targetsFunction(string $name): bool
    {
        return $this->function === ltrim($name, '\\');
    }
}
