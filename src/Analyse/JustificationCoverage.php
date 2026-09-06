<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PHPStan\Node\CollectedDataNode;
use Pushery\SQLens\Attributes\RawSql;

/**
 * Whether a call site is covered by a `#[RawSql]` annotation — asked once, for both channels.
 *
 * ## Two joins, because an annotation has two ways of reaching a call
 *
 * - **By NAME.** A call inside `App\Report::build()` is covered by an annotation on the method OR
 *   on its class, so both names are tried. An anonymous class counts: it IS a class, PHPStan gives
 *   it a synthetic name both sides of the join agree on, and it is the shape every Laravel
 *   migration takes — which is where raw DDL lives.
 * - **By POSITION.** A free function, a closure and an arrow function report no scope name at all,
 *   so there is nothing for an equality join to compare. `#[RawSql]` has declared `TARGET_FUNCTION`
 *   since it was written, and for a long time nothing read it there — which made the duty
 *   impossible to discharge in a Pest suite, whose every test body is a file-scope closure. The
 *   span is the whole node, so a nested closure inside an annotated one is covered too: the same
 *   reach a method-level annotation has over its own body.
 *
 * ## Why it is a unit and not a method on the rule that had it
 *
 * Two rules now ask this question of two different channels — {@see UnjustifiedRawSqlRule} of the
 * policy answer, {@see RawInterpolationRule} of the interpolation answer — and a second copy of the
 * join is the failure this package has already paid for once elsewhere: two readings that agree
 * today and disagree the first time either is touched, each looking correct on its own, and each
 * rule's tests green about its own half.
 *
 * ## The CHANNEL is chosen by the caller, and the two never merge
 *
 * `reason:` answers *"why raw SQL"*; `interpolation:` answers *"why a runtime value is in the
 * statement's text"*. A method reasoned *"we need a window function"* has said nothing about an
 * interpolated value inside it, so reading one channel as the other would switch the injection rule
 * off wherever the policy annotation is on. See {@see RawSql} for the decision.
 */
final readonly class JustificationCoverage
{
    /**
     * @param  list<string>  $names  every class and method carrying an accepted annotation
     * @param  array<string, list<array{from: int, to: int}>>  $spans  annotated line ranges, per FILE
     */
    private function __construct(private array $names, private array $spans) {}

    /** Coverage by the policy answer — `#[RawSql(reason: '…')]`. */
    public static function rawSql(CollectedDataNode $node): self
    {
        return self::of($node, interpolationChannel: false);
    }

    /** Coverage by the interpolation answer — `#[RawSql(interpolation: '…')]`. */
    public static function interpolation(CollectedDataNode $node): self
    {
        return self::of($node, interpolationChannel: true);
    }

    /**
     * Is this call site covered?
     *
     * @param  string|null  $scope  the class-or-method name the call site reported itself under
     */
    public function covers(?string $scope, string $file, int $line): bool
    {
        return $this->byName($scope) || $this->byPosition($file, $line);
    }

    /**
     * The channel is a flag rather than a key name, and that is a typing decision rather than a
     * style one: a variable array key loses the shape the collectors declare, so PHPStan can no
     * longer tell that `names` holds strings. Literal keys keep the guarantee, and the two named
     * factories above are what a caller reads.
     */
    private static function of(CollectedDataNode $node, bool $interpolationChannel): self
    {
        $names = [];

        foreach ($node->get(JustificationCollector::class) as $perFile) {
            foreach ($perFile as $entry) {
                // Positive form, and it is not a style choice: the collector answers `array|null`
                // and PHPStan filters the nulls, so a `! is_array(…) { continue; }` is a line no run
                // can enter — which the 100% floor reports as uncovered and no honest test can
                // close. The shape this was lifted from wrote it this way for the same reason.
                if (is_array($entry)) {
                    foreach ($interpolationChannel ? $entry['interpolationNames'] : $entry['names'] as $name) {
                        $names[] = $name;
                    }
                }
            }
        }

        $spans = [];

        // Per FILE, because a line number means nothing on its own: line 42 of one file and line 42
        // of another are not the same place, and a flat list of ranges would cover a call site in a
        // file carrying no annotation at all — silently, and in the direction that hides findings.
        foreach ($node->get(JustificationSpanCollector::class) as $file => $perFile) {
            foreach ($perFile as $entry) {
                if (is_array($entry) && ($interpolationChannel ? $entry['interpolation'] : $entry['rawSql'])) {
                    $spans[(string) $file][] = ['from' => $entry['from'], 'to' => $entry['to']];
                }
            }
        }

        return new self($names, $spans);
    }

    private function byName(?string $scope): bool
    {
        if ($scope === null) {
            return false;
        }

        if (in_array($scope, $this->names, true)) {
            return true;
        }

        $class = str_contains($scope, '::') ? substr($scope, 0, (int) strpos($scope, '::')) : $scope;

        return in_array($class, $this->names, true);
    }

    private function byPosition(string $file, int $line): bool
    {
        return array_any(
            $this->spans[$file] ?? [],
            static fn (array $span): bool => $line >= $span['from'] && $line <= $span['to'],
        );
    }
}
