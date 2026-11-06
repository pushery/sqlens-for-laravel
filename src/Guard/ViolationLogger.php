<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Illuminate\Contracts\Events\Dispatcher;
use Psr\Log\LoggerInterface;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Guard\Events\ViolationRecorded;
use Pushery\SQLens\Guard\Violations\Violation;
use Pushery\SQLens\Security\SecretLiteralMask;
use Pushery\SQLens\Severity\Severity;
use Throwable;

/**
 * Where every guard violation goes — one place, one shape, one set of redaction rules.
 *
 * ## Why the guardrails do not log for themselves
 *
 * Four guardrails logging directly would be four places that decide whether bindings are included,
 * four truncation lengths and four chances for one of them to forget. Row data reaching a log is
 * not a formatting detail: a log is the one destination where database contents land somewhere with
 * different access rules than the database they came from, and it is usually shipped off the host.
 *
 * ## Redaction is not optional, even when bindings are asked for
 *
 * `include_bindings = true` does not mean "log the values". It means "log their shape" — type and
 * length, never content. A binding can be a password, a token or somebody's address, and the
 * question a developer actually has ("did it bind a string or an integer, and was it empty?") is
 * answered completely by the shape.
 *
 * ## The statement's own literals are shapes too
 *
 * A value written into the statement text is the same row data as a bound one, and `unbound_raw_sql`
 * selects exactly the statements that carry one. So every literal in a logged statement becomes its
 * length, `'alice@example.com'` becoming `'<string(17)>'`, whatever `include_bindings` says. Where a
 * literal ends is a question of the engine's grammar, read from the connection's registered
 * canonicalization; an engine without one has everything from its first quote to its last masked,
 * because any other guess can end a literal early and log the rest of it as text.
 *
 * ## Severity RAISES the level; the profile level is a floor
 *
 * A `security` violation and a slow query at the same profile level would otherwise arrive as the
 * same log line, and the axis this package keeps separate everywhere else would be flattened in the
 * one output somebody pages on.
 *
 * ## A listener reads the same record
 *
 * Each record is dispatched as {@see ViolationRecorded} as well, with the context of the log line,
 * so a listener that hands findings on, an APM client among them, reads them without parsing log
 * lines. A record is rare next to the statements it is about, so the event goes out whether or not
 * anybody listens, and a test can assert on it through `Event::fake()`.
 *
 * ## What it never does
 *
 * It does not throw on a logging failure. A logger that is misconfigured must not become the reason
 * a request fails — the guardrail was already reporting something the application survived, and
 * turning that into a fatal would be the guard causing the outage it was watching for. The channel
 * and the level are validated at BOOT ({@see GuardProfile::resolve()}) precisely so this path stays
 * quiet.
 */
final readonly class ViolationLogger
{
    /**
     * How each PSR-3 level ranks, so a severity can raise one without a table of pairs.
     *
     * @var array<string, int>
     */
    private const array RANK = [
        'debug' => 0, 'info' => 1, 'notice' => 2, 'warning' => 3,
        'error' => 4, 'critical' => 5, 'alert' => 6, 'emergency' => 7,
    ];

    /** What a security severity demands at least. Below these, the profile's own level stands. */
    private const array SEVERITY_FLOOR = [
        'info' => 'info',
        'low' => 'notice',
        'medium' => 'warning',
        'high' => 'error',
        'critical' => 'critical',
    ];

    /**
     * @param  LoggerInterface  $log  already pointed at the profile's channel.
     *
     * PSR-3 and not Laravel's log manager, deliberately. This class needs to write a line at a
     * level with a context array, and that is the whole of PSR-3 — depending on the manager would
     * pull the framework's logging package into a library whose other dependencies are focused
     * `illuminate/*` components. Which CHANNEL to write to is a resolution question, and it happens
     * once at boot where the channel's existence is validated anyway.
     */
    public function __construct(
        private LoggerInterface $log,
        private ?CanonicalExtensionRegistry $grammars = null,
        private ?Dispatcher $events = null,
    ) {}

    public function record(GuardProfile $profile, Violation $violation): void
    {
        $context = $violation->contextFor(
            $profile->name,
            $violation->sql === null ? null : $this->clipped($this->withoutLiteralValues($violation->sql, $violation->connection), $profile->maxSqlLength),
            $profile->includeBindings ? $this->shapes($violation->bindings) : null,
        );

        $level = $this->level($profile, $violation);

        try {
            $this->log->log($level, 'sqlens.guard: '.$violation->message, $context);
        } catch (Throwable) {
            // Deliberately silent. See the class docblock: a guardrail must never be the reason a
            // request fails, and the one configuration error that could reach here is refused at
            // boot instead.
        }

        $this->announce($profile, $violation, $level, $context);
    }

    /**
     * Dispatch the record to whoever listens, with the context the log line went out with.
     *
     * A listener runs inside the report, and what it does can be a finding of its own. A lazy load
     * it triggers reaches the same handler before the relation loads, so a listener that reads the
     * relation a finding named would be handed its own finding again, as deep as the stack goes; a
     * listener that runs a slow statement for every finding would do the same. A finding that
     * arises while one is announced is therefore logged like any other and not announced again.
     *
     * Silent on failure for the reason the log is: a listener that throws must not turn a finding
     * the application survived into a failed request.
     *
     * @param  array<string, mixed>  $context
     */
    private function announce(GuardProfile $profile, Violation $violation, string $level, array $context): void
    {
        /** @var bool $announcing set while a listener runs, and read by a finding that arises inside it */
        static $announcing = false;

        $events = $this->events;

        if ($announcing || ! $events instanceof Dispatcher) {
            return;
        }

        $sql = $context['sql'] ?? null;
        $announcing = true;

        try {
            $events->dispatch(new ViolationRecorded($profile->name, $violation->type, $level, $violation->message, is_string($sql) ? $sql : null, $context));
        } catch (Throwable) {
            // Deliberately silent, as above.
        } finally {
            $announcing = false;
        }
    }

    /**
     * The level this record goes out at: the profile's, raised by a security severity.
     *
     * Raised and never LOWERED. A profile that logs at `error` has said what it wants to see, and a
     * severity quietly demoting a record below that would hide it from the filter somebody set up.
     */
    private function level(GuardProfile $profile, Violation $violation): string
    {
        $configured = $profile->logLevel;

        if (! $violation->severity instanceof Severity) {
            // An undetermined record never rides a severity — there is no verdict to rate — so it
            // arrives at the profile's own level, where a reader filtering for problems still sees
            // it. Dropping it to `debug` would hide the case this package cares most about.
            return $configured;
        }

        // No `??` on either lookup: `SEVERITY_FLOOR` covers every case of the enum and `RANK` every
        // PSR-3 level the config schema accepts, so a fallback here would be a branch nothing can
        // enter — untestable, unable to go red, and load-bearing for the level a reader filters on.
        $floor = self::SEVERITY_FLOOR[$violation->severity->value];

        return self::RANK[$floor] > (self::RANK[$configured] ?? 0) ? $floor : $configured;
    }

    /**
     * Bindings as SHAPES: type and length, never content.
     *
     * `include_bindings = true` asks to see what was bound, not what the values were. A binding can
     * be a password, a token or somebody's address, and "string(24)" answers the question a
     * developer actually has — did it bind a string or an integer, and was it empty — without
     * putting row data into a file that leaves the host.
     *
     * @param  array<array-key, mixed>  $bindings
     * @return array<array-key, string>
     */
    private function shapes(array $bindings): array
    {
        return array_map(static fn (mixed $value): string => match (true) {
            is_string($value) => sprintf('string(%d)', mb_strlen($value)),
            // Booleans and null are printed outright: neither can carry a secret, and knowing which
            // of `false`, `null` and `0` was bound is the whole question in a WHERE clause that
            // matched nothing.
            is_bool($value) => $value ? 'true' : 'false',
            $value === null => 'null',
            is_int($value), is_float($value) => get_debug_type($value),
            default => get_debug_type($value),
        }, $bindings);
    }

    /**
     * The statement with every literal replaced by its shape, in the grammar of the connection it ran
     * on.
     *
     * Masked before anything else touches it, the credential mask and the clip included: both read
     * the statement's literals, and a clip that cut one in half would leave a fragment no grammar
     * reads as a literal any more.
     *
     * The lookup is caught rather than trusted. A driver's canonicalization can be a third party's,
     * and a guardrail must never become the reason a request fails; the coarse mask is the answer
     * that stays correct without a grammar.
     */
    private function withoutLiteralValues(string $sql, ?string $connection): string
    {
        try {
            $grammar = $connection === null ? null : $this->grammars?->forConnection($connection);
        } catch (Throwable) {
            $grammar = null;
        }

        return $grammar instanceof DriverCanonicalization
            ? StringLiteralMask::forDriver($grammar)->shaped($sql)
            : StringLiteralMask::coarse($sql);
    }

    /**
     * The SQL, cut to the profile's length, with the cut MARKED.
     *
     * Named `clipped` rather than `truncate` on purpose: `NoDatabaseWriteArchTest` scans the shipped
     * tree for writing verbs, and `->truncate()` is one — `TRUNCATE TABLE` is the most destructive
     * statement there is. A guard that had to learn an exception for this method would be a guard
     * with a hole in it, and the method does not need that name.
     *
     * An unmarked truncation is worse than a long line: somebody reading the log sees a statement
     * that appears to end where it does not, and reasons about a `WHERE` clause that is simply not
     * shown.
     */
    private function clipped(string $sql, int $max): string
    {
        // Masked before it is clipped. Bindings are shape-only by design — the class docblock
        // argues that at length — and the statement text needs the same care: a
        // `CREATE ROLE … PASSWORD 'literal'` or an `IDENTIFIED BY '…'` running at runtime would
        // otherwise write its credential into the application's own log channel, which is usually
        // the most widely readable surface a request touches. This package has a rule for that
        // mistake in a migration; its runtime half must not publish it.
        //
        // The order is the load-bearing half, not the masking. Clipping first can cut a statement
        // mid-literal — `… PASSWORD 'hunter` — and the truncated form matches no shape the mask
        // knows, so the fragment would survive exactly in the case where the value is longest and
        // the clip most likely. Mask first and the clip only ever shortens a line whose secrets are
        // already gone.
        $sql = SecretLiteralMask::in($sql);

        // `mb_strcut` and not `substr`: cutting a multi-byte statement mid-character produces bytes
        // no log viewer can render, and a JSON-encoding handler then drops the whole record.
        return mb_strlen($sql) <= $max ? $sql : mb_strcut($sql, 0, $max).'… [truncated by sqlens.guard]';
    }
}
