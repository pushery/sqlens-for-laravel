<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Name;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogEntry;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogTarget;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalog;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalogs;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Exceptions\InvalidPreScanCatalog;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * Closes the most common way around the side-effect catalog: a migration that
 * reaches its effect through the application's OWN code.
 *
 *     public function up(): void
 *     {
 *         (new UserBackfill)->run();          // and run() sends a Notification
 *         app(Importer::class)->handle();     // resolved from the container
 *     }
 *
 * Such a call resolves cleanly — it is not the dynamic indirection the AST
 * substrate flags — and it appears in no hand-written catalog of framework
 * surfaces. Left alone it is a silent `pass`, and the product disaster (a lint
 * run that mails a customer) happens one level below where the side-effect
 * detector was looking.
 *
 * **The decision this detector embodies.** The detector does NOT follow the call
 * into the target class — it is pattern detection, not taint analysis. It cannot
 * know whether `UserBackfill::run()` sends a notification or formats a string. So
 * it could either leave the case as a named honesty limit ("the pre-scan sees one
 * level") or flag it conservatively. It flags: the honesty limit would sit
 * exactly where the disaster happens, `undetermined` costs the user only a shadow
 * run, and a silent `pass` costs a sent message. The finding says plainly that a
 * helper call from a migration is common and fine — the point is that pretend
 * cannot see what it does, not that the call is wrong.
 *
 * **What is deliberately NOT a hit,** so the rule is not noise:
 *
 * - A call on `$this` (the migration's own method or a trait method mixed into
 *   it). Flagging every migration that factored code into a private helper would
 *   make the rule unusable; own methods live in the same file the pre-scan
 *   already covers.
 * - The whole framework (`Illuminate\*`) and a short list of pure value surfaces
 *   (Carbon, DateTime, Uuid). These are handled by their own detectors or do no
 *   database work at all.
 * - Anything on the project's own allowlist (`sqlens.capture.prescan
 *   .indirect_calls.allowlist`), where a team has stated a class is safe.
 * - Pure value construction with no call (`new X(...)` as an argument,
 *   `Status::Active`, a constant) never reaches here — it is not a call node.
 */
final readonly class IndirectCallDetector implements PreScanDetector
{
    public const string RULE_ID = 'CAP.PRESCAN.INDIRECT_CALL';

    /** Where an application declares classes an indirect-call hit is not raised for. */
    public const string CONFIG_PATH = 'sqlens.capture.prescan.indirect_calls.allowlist';

    /** The container resolvers whose `X::class` argument names the real receiver. */
    private const array CONTAINER_RESOLVERS = ['app', 'make', 'resolve'];

    private PreScanCatalog $exempt;

    /** @var list<CatalogTarget> */
    private array $allowlist;

    /**
     * @param  list<string>  $allowlist  extra exempt classes/namespaces from config
     */
    public function __construct(?PreScanCatalogs $catalogs = null, array $allowlist = [])
    {
        $this->exempt = ($catalogs ?? PreScanCatalogs::bundled())->catalog(PreScanCatalogs::INDIRECT_CALL_EXEMPT);

        $this->allowlist = array_map(
            // Already validated by the config validator before a run; a malformed
            // entry here is a bug in that path, so it throws rather than silently
            // failing to widen the allowlist — which would leave a project flagged
            // for a class it thought it had exempted.
            static fn (string $written): CatalogTarget => self::allowlistTarget($written, self::CONFIG_PATH),
            $allowlist,
        );
    }

    public function metadata(): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: self::RULE_ID,
            category: Category::Safety,
            level: Level::Capturable,
            severity: null,
            // Preview, not stable: unlike the framework-surface catalogs, this
            // flags a whole class of project calls without looking inside them,
            // so its false-positive rate is real and has to be measured against a
            // corpus before it is promoted.
            stability: StabilityTier::Preview,
            deprecation: null,
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A pre-scan hit describes no DDL — it is the reason a migration was not captured at all — so it has no downtime behavior to classify.',
            messagePrefix: 'Indirect call from migration',
            documentationUrl: RuleDocumentationUrl::for(self::RULE_ID),
            suites: PreScanMetadataAudit::defaultSuites(),
            badExample: <<<'PHP'
                public function up(): void
                {
                    Schema::table('users', fn (Blueprint $t) => $t->string('slug')->nullable());

                    // run() might send a notification or hit an API — pretend runs it
                    // for real and the capture cannot see what it does.
                    (new UserBackfill)->run();
                }
                PHP,
            goodExample: <<<'PHP'
                public function up(): void
                {
                    Schema::table('users', fn (Blueprint $t) => $t->string('slug')->nullable());
                }

                // The backfill is a job the deploy dispatches after the migration, or
                // a shadow run captures it against a throwaway database. If the class
                // is known-safe, add it to
                // sqlens.capture.prescan.indirect_calls.allowlist.
                PHP,
        );
    }

    public function detect(ScannedMigration $migration): array
    {
        $hits = [];
        $seenLines = [];

        foreach ($migration->migrationCalls() as $call) {
            $class = $this->targetClass($call);
            if ($class === null) {
                continue;
            }
            if ($this->isExempt($class)) {
                continue;
            }
            if (in_array($call['line'], $seenLines, true)) {
                continue;
            }

            $hits[] = new PreScanHit(
                self::RULE_ID,
                $migration->file,
                $call['line'],
                sprintf(
                    'The migration calls into %s at line %d, code the static pre-scan cannot follow. A helper call from a migration is common and fine — the point is that pretend mode runs it for real without seeing what it does, so it could fire a side effect or depend on data. Move it into a job the deploy dispatches, capture in shadow mode, or add %s to sqlens.capture.prescan.indirect_calls.allowlist if it is known-safe.',
                    $class,
                    $call['line'],
                    $class,
                ),
                $call['target']->description,
            );
            $seenLines[] = $call['line'];
        }

        return $hits;
    }

    /**
     * The external class a call reaches, or null when it reaches none the
     * detector is concerned with.
     *
     * Three shapes resolve to a class: a static call (`Foo::bar()`), an instance
     * call on a freshly constructed receiver (`(new Foo)->bar()`), and a call on
     * a container-resolved receiver (`app(Foo::class)->bar()`). A call on `$this`
     * or on a variable of unknown type resolves to no class and is left alone.
     *
     * @param  array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}  $call
     */
    private function targetClass(array $call): ?string
    {
        $target = $call['target'];

        // A dynamic call is the AST substrate's concern, with its own reason.
        if ($target->isDynamic) {
            return null;
        }

        // A static call or a `(new Foo)->bar()` already carries its class.
        if ($target->class !== null) {
            return $target->class;
        }

        // A method call whose receiver is `app(Foo::class)` / make / resolve —
        // the container hands back an instance of the named class.
        return $call['node'] instanceof MethodCall ? $this->containerResolvedClass($call['node']) : null;
    }

    /** The class `app(Foo::class)->m()` (or make/resolve) resolves its receiver to, if any. */
    private function containerResolvedClass(MethodCall $node): ?string
    {
        if (! $node->var instanceof FuncCall || ! $node->var->name instanceof Name) {
            return null;
        }

        if (! in_array($this->functionName($node->var->name), self::CONTAINER_RESOLVERS, true)) {
            return null;
        }

        // `app(...)` with no argument, or a spread, resolves nothing nameable.
        $first = $node->var->args[0] ?? null;

        if (! $first instanceof Arg) {
            return null;
        }

        // `Foo::class` is a ClassConstFetch on a resolved Name — that name is the
        // class the container will build.
        $argument = $first->value;

        return $argument instanceof ClassConstFetch && $argument->class instanceof Name
            ? $this->resolvedName($argument->class)
            : null;
    }

    private function isExempt(string $class): bool
    {
        $target = CallTarget::staticCall($class, '__any__');

        if ($this->exempt->match($target) instanceof CatalogEntry) {
            return true;
        }

        return array_any($this->allowlist, fn (CatalogTarget $entry): bool => $entry->matches($target));
    }

    private function functionName(Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ltrim($resolved instanceof Name ? $resolved->toString() : $name->toString(), '\\');
    }

    private function resolvedName(Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');

        return ltrim($resolved instanceof Name ? $resolved->toString() : $name->toString(), '\\');
    }

    /**
     * Parse one allowlist entry into a matchable target. Only a bare class or a
     * namespace prefix is meaningful here — a method or function form would name
     * something an indirect-call hit never carries, so it is rejected rather than
     * silently never matching.
     */
    private static function allowlistTarget(string $written, string $origin): CatalogTarget
    {
        if (! self::acceptsAllowlistEntry($written)) {
            throw InvalidPreScanCatalog::malformedTarget($origin, trim($written));
        }

        return CatalogTarget::parse($written, $origin);
    }

    /**
     * Whether a written allowlist entry is a class or a namespace prefix — the
     * predicate the config validator asks, so a typo is a named violation rather
     * than an exemption that quietly never applies.
     */
    public static function acceptsAllowlistEntry(string $written): bool
    {
        $target = CatalogTarget::tryParse($written);

        // A class (`class` set, no method) or a namespace prefix — never a method,
        // function, or receiver-agnostic form.
        return $target instanceof CatalogTarget
            && $target->method === null
            && $target->function === null
            && ($target->class !== null || $target->namespacePrefix !== null);
    }
}
