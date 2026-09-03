<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * The query side of the online-DDL matrix: from a canonical operation key, the server version
 * the run reasons about, and what the capture knows about the table, resolve the single
 * applicable {@see MatrixEntry} — or a named undetermined.
 *
 * It is deterministic and strictly read-only: it touches only the already-loaded matrix, never
 * a database (primum non nocere). The version it reasons about is the driver-neutral
 * {@see ResolvedServerVersion} the rest of the package resolves once — this resolver builds no
 * MySQL-own version type, so there is a single source for "which version", and the determinism
 * promise (pin wins, else the real connection, else a named unknown) holds here unchanged.
 *
 * Four things it will never do: guess a COPY for an operation it does not know; borrow the
 * matrix file's `reference_server` when no version was resolved; assume the cheap path when a
 * gating fact is unreadable; or pick between overlapping version windows. The first three are a
 * named undetermined; the last is a data error, because two entries claiming the same operation
 * at the same version is a bug in the matrix, not a runtime uncertainty.
 */
final readonly class MatrixResolver
{
    /** Only carried onto parsed versions for display; version comparison ignores the driver. */
    private const string DRIVER = 'mysql';

    public function __construct(private OnlineDdlMatrix $matrix) {}

    public static function bundled(): self
    {
        return new self(OnlineDdlMatrix::bundled());
    }

    public function resolve(string $operation, ResolvedServerVersion $version, MatrixContext $context): MatrixResolution
    {
        $resolved = $version->version;

        // No version, no verdict. The reference_server field is documentation, never a
        // resolution default — falling back to it would make the fast path silently claim a
        // version it never had. The reason rides along from the resolver that failed.
        if (! $resolved instanceof ServerVersion) {
            return MatrixResolution::undetermined(
                $version->reason ?? UndeterminedReason::UnknownServerVersion,
                'the server version could not be resolved, so this operation\'s online-DDL behavior is unknown',
            );
        }

        $candidates = array_values(array_filter(
            $this->matrix->all(),
            static fn (MatrixEntry $entry): bool => $entry->operation === $operation,
        ));

        if ($candidates === []) {
            return MatrixResolution::undetermined(
                UndeterminedReason::UnclassifiedOnlineDdlOperation,
                "operation '{$operation}' is not classified in the online-DDL matrix",
            );
        }

        $applicable = array_values(array_filter(
            $candidates,
            fn (MatrixEntry $entry): bool => $this->coversVersion($entry, $resolved),
        ));

        if ($applicable === []) {
            return MatrixResolution::undetermined(
                UndeterminedReason::OnlineDdlVersionOutOfRange,
                "no online-DDL entry for '{$operation}' at MySQL {$resolved->toString()}",
            );
        }

        return $this->applyConditions($this->narrowest($applicable, $operation, $resolved), $context);
    }

    /**
     * Gate the resolved entry on its conditions. Each condition names a predicate from the
     * fixed vocabulary; an undecidable one is undetermined, a decided-against-safe one means
     * the entry does not apply. A condition naming no known predicate is a data error — a
     * silently non-gating condition is the exact silent green this package exists to prevent.
     */
    private function applyConditions(MatrixEntry $entry, MatrixContext $context): MatrixResolution
    {
        foreach ($entry->conditions as $condition) {
            $predicate = OnlineDdlPredicate::tryFrom($condition->id);

            if (! $predicate instanceof OnlineDdlPredicate) {
                throw InvalidRuleEvidence::malformed(
                    OnlineDdlMatrix::BUNDLED_FILE,
                    "entries.{$entry->id}.conditions",
                    "condition '{$condition->id}' to name a known online-DDL predicate",
                );
            }

            $decided = $context->decide($predicate);

            if ($decided === null) {
                return MatrixResolution::undetermined(UndeterminedReason::OnlineDdlConditionUndecidable, $condition->id);
            }

            if ($decided !== $predicate->safeValue()) {
                return MatrixResolution::undetermined(UndeterminedReason::OnlineDdlConditionViolated, $condition->id);
            }
        }

        return MatrixResolution::resolved($entry);
    }

    /** Whether the resolved version falls within the entry's [min, max] window (max null = open). */
    private function coversVersion(MatrixEntry $entry, ServerVersion $version): bool
    {
        [$min, $max] = $this->bounds($entry);

        if ($version->isBelow($min)) {
            return false;
        }

        return ! $max instanceof ServerVersion || ! $max->isBelow($version);
    }

    /**
     * The one entry that applies at this version. With disjoint version windows exactly one
     * matches; with nested windows (a general entry plus a version-specific override) the
     * innermost wins. Two windows that overlap without one strictly inside the other — or two
     * with identical bounds — is a data error, never a silent pick.
     *
     * @param  list<MatrixEntry>  $applicable
     */
    private function narrowest(array $applicable, string $operation, ServerVersion $version): MatrixEntry
    {
        $innermost = array_values(array_filter(
            $applicable,
            fn (MatrixEntry $candidate): bool => $this->isInnermost($candidate, $applicable),
        ));

        if (count($innermost) === 1) {
            return $innermost[0];
        }

        throw InvalidRuleEvidence::malformed(
            OnlineDdlMatrix::BUNDLED_FILE,
            "entries[operation={$operation}]",
            "one entry to apply at MySQL {$version->toString()}, but the version windows overlap without a clear narrowest",
        );
    }

    /**
     * Whether $candidate's window is strictly inside every OTHER applicable entry's window —
     * the test for "most specific".
     *
     * @param  list<MatrixEntry>  $applicable
     */
    private function isInnermost(MatrixEntry $candidate, array $applicable): bool
    {
        foreach ($applicable as $other) {
            if ($other === $candidate) {
                continue;
            }

            if (! $this->strictlyContains($other, $candidate)) {
                return false;
            }
        }

        return true;
    }

    /** $inner's window sits inside $outer's and is not equal to it. */
    private function strictlyContains(MatrixEntry $outer, MatrixEntry $inner): bool
    {
        return $this->contains($outer, $inner) && ! $this->contains($inner, $outer);
    }

    /** Whether $inner's [min, max] is entirely within $outer's, treating a null max as open. */
    private function contains(MatrixEntry $outer, MatrixEntry $inner): bool
    {
        [$outerMin, $outerMax] = $this->bounds($outer);
        [$innerMin, $innerMax] = $this->bounds($inner);

        if ($innerMin->isBelow($outerMin)) {
            return false;
        }

        if (! $outerMax instanceof ServerVersion) {
            return true;
        }

        return $innerMax instanceof ServerVersion && ! $outerMax->isBelow($innerMax);
    }

    /**
     * The entry's parsed version bounds. min_version is required, so the lower bound is always
     * present; max_version is optional (null = open above). A version string the entry carries
     * that cannot be read is a data error, not a silent skip.
     *
     * @return array{0: ServerVersion, 1: ?ServerVersion}
     */
    private function bounds(MatrixEntry $entry): array
    {
        return [
            $this->parseVersion($entry->minVersion, $entry),
            $entry->maxVersion === null ? null : $this->parseVersion($entry->maxVersion, $entry),
        ];
    }

    private function parseVersion(string $raw, MatrixEntry $entry): ServerVersion
    {
        $parsed = ServerVersion::parsePin($raw, self::DRIVER);

        if (! $parsed instanceof ServerVersion) {
            throw InvalidRuleEvidence::malformed(
                OnlineDdlMatrix::BUNDLED_FILE,
                "entries.{$entry->id}.version",
                "a readable version, got \"{$raw}\"",
            );
        }

        return $parsed;
    }
}
