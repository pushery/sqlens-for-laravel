<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server whose default transaction isolation is not `read committed`.
 *
 * ## What actually goes wrong
 *
 * Laravel and Eloquent are written against `read committed`. Raise the server default and the
 * framework's own transactions — and every one an application opens without thinking about it —
 * start being able to fail with a serialization error. That failure is a `40001`, it is retryable
 * by design, and almost no application code written against the framework retries it, because on
 * `read committed` it never happens.
 *
 * The shape of the failure is what makes it worth reporting: it does not appear in development, it
 * does not appear under light traffic, and it appears under concurrency — which is the moment
 * nobody wants to be discovering a new error class.
 *
 * ## Why this rule is deliberately not dogmatic
 *
 * A higher isolation level is a legitimate architectural decision. Some applications genuinely want
 * `serializable` and have written retry handling to match; telling those teams they have a defect
 * would be wrong, and a rule that brands a considered decision as an error is a rule people switch
 * off — taking the rest of the suite with it.
 *
 * So the finding says what the consequence IS and names the decision it might be, rather than
 * asserting a mistake. It is also the reason this rule reports {@see Confidence::Heuristic}: what it
 * can see is the setting, and what it cannot see is whether the application was built for it.
 *
 * ## One rule, one statement
 *
 * `default_transaction_read_only` is a separate finding with its own id, not extra context hung on
 * this one. Two independent claims under one identity would make a single ignore-list entry silence
 * both, and a reader could not tell which of them they had accepted.
 */
final class DefaultTransactionIsolationDriftRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L6.DEFAULT_TRANSACTION_ISOLATION_DRIFT';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    /**
     * Heuristic, and honestly so.
     *
     * The setting is read exactly; what is inferred is that the application was not built for it.
     * That inference is usually right and is not always right, and a rule claiming determinism here
     * would be overstating what it knows — which is the same overreach as reporting a considered
     * decision as a defect.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'default_transaction_isolation';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $expected = $expectation->expectation ?? 'read committed';

        // PostgreSQL reports the level lower-cased and spaced (`repeatable read`), but a value that
        // arrived through a config file may be spelled differently. Folded on both case and internal
        // spacing so `Repeatable  Read` is recognized as the same level rather than reported as a
        // third, unknown one.
        if ($this->fold($serverValue) === $this->fold($expected)) {
            return null;
        }

        return sprintf(
            'the server defaults transactions to %s rather than %s. Laravel and Eloquent are written '.
            'against %s, so at %s the framework\'s own transactions can fail with a serialization '.
            'error (SQLSTATE 40001) that application code written against the framework does not '.
            'retry — and that failure appears under concurrency rather than in development. If the '.
            'higher level is a deliberate decision and the retry handling exists, this is the '.
            'expected case to add to the ignore list, with the reason recorded there. %s',
            $serverValue,
            $expected,
            $expected,
            $serverValue,
            $this->remediation($expectation),
        );
    }

    /** Case- and spacing-insensitive, because an isolation level is a keyword phrase, not data. */
    private function fold(string $value): string
    {
        return strtolower((string) preg_replace('/\s+/', ' ', trim($value)));
    }
}
