<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Attributes\SqlensIgnore;
use Pushery\SQLens\Subjects\MigrationSql;
use ReflectionAttribute;
use ReflectionClass;

/**
 * Reads the `#[SqlensIgnore]` annotations off a migration subject's class — by
 * reflection, never by parsing the file or matching a regex. The suppressions it
 * returns apply ONLY to findings of that same subject: a migration can never
 * suppress another migration's findings.
 *
 * It never autoloads a class off disk (`class_exists` with autoload disabled): only
 * a migration class already loaded by the capture path is reflected, so a crafted
 * subject cannot pull an arbitrary class into memory. Applying the suppression to a
 * finding — stamping it with the `annotation` source and the reason — is the
 * resolver's job; this source only surfaces the annotations and their reasons.
 */
final readonly class AnnotationSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'annotation';

    /**
     * The SqlensIgnore annotations declared on the subject's migration class.
     *
     * @return list<SqlensIgnore>
     */
    public function annotations(MigrationSql $subject): array
    {
        // The REAL class of the loaded migration instance, not the migration name.
        // Laravel's migrations are anonymous classes, whose name is nothing like the
        // file basename the repository records — reflecting the basename would find no
        // class and silently suppress nothing, which is the no-op this package refuses
        // everywhere else. PHP's mangled anonymous-class name reflects fine while the
        // instance is loaded, which it is by the time a finding exists.
        return $this->forClass($subject->annotationClass);
    }

    /**
     * The same reading, from a class name rather than a subject.
     *
     * The lint run validates the rule ids these annotations name, and it holds `CaptureResult`s
     * rather than subjects at that point. Reading the attributes a second time there would be a
     * second answer to "what does this migration annotate" — and the two would agree until the
     * day one of them learned about a new attribute target.
     *
     * @return list<SqlensIgnore>
     */
    public function forClass(?string $class): array
    {
        if ($class === null || ! class_exists($class, autoload: false)) {
            return [];
        }

        return array_map(
            static fn (ReflectionAttribute $attribute): SqlensIgnore => $attribute->newInstance(),
            new ReflectionClass($class)->getAttributes(SqlensIgnore::class),
        );
    }

    /**
     * The annotation suppressing the given rule for this subject, or null. The first
     * matching annotation wins, deterministically (declaration order).
     */
    public function suppressionFor(MigrationSql $subject, string $ruleId): ?SqlensIgnore
    {
        foreach ($this->annotations($subject) as $annotation) {
            if ($annotation->suppresses($ruleId)) {
                return $annotation;
            }
        }

        return null;
    }
}
