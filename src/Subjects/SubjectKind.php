<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * The three subject sources the one rule engine dispatches over. EXACTLY three:
 * captured migration SQL, a live catalog object, a PHP raw-SQL callsite.
 *
 * Statistics are context on a finding, not a fourth subject — a test forbids a
 * fourth value here.
 */
enum SubjectKind: string
{
    case MigrationSql = 'migration_sql';
    case SchemaObject = 'schema_object';
    case RawSql = 'raw_sql';
}
