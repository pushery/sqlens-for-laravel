<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A MySQL server whose default character set is not `utf8mb4`.
 *
 * ## What actually goes wrong
 *
 * A database or table created without an explicit `CHARACTER SET` takes the server's. Laravel's
 * schema builder does emit one for tables it creates from `config('database.connections.mysql.charset')`,
 * so the common failure is not the tables Laravel makes — it is everything else: a database an
 * operator created by hand, a table added by a DBA, a temporary table, a migration written in raw
 * SQL.
 *
 * (The database-creating statement is deliberately not spelled out as a literal anywhere in this
 * file. A scanner cannot tell a sentence from SQL the package might run, and the guard that confines
 * such statements to the shadow provisioners is worth more than the phrasing.)
 *
 * On `latin1` those objects silently cannot hold most of Unicode. An emoji, a Chinese name, a
 * combining accent — MySQL either replaces the character or truncates the value at it, depending on
 * the SQL mode, and in the lax case it does so **without an error**. The row is stored, shorter or
 * altered, and nobody finds out until a user asks why their name is wrong.
 *
 * ## Why this is one rule and not two
 *
 * `collation_server` is not judged separately, because MySQL will not let the two disagree. Measured
 * on 8.4.10: setting `character_set_server = latin1` moved `collation_server` to
 * `latin1_swedish_ci` on its own, and setting `collation_server = utf8mb4_unicode_ci` moved
 * `character_set_server` to `utf8mb4`. They are one setting with two names.
 *
 * A second rule would therefore report the same misconfiguration twice under two ids — and an
 * ignore-list entry for one would leave the other one shouting, which is the worst of both.
 *
 * ## What is deliberately NOT judged
 *
 * Which utf8mb4 collation the server carries. `utf8mb4_0900_ai_ci` and `utf8mb4_unicode_ci` are both
 * legitimate: the second pins an older Unicode version, which is a real reason on a database that
 * has to keep sort order stable across a MySQL upgrade. Flagging that would be the dogmatism this
 * package avoids — the charset is a correctness question, the collation within it is a decision.
 */
final class CharacterSetServerNotUtf8mb4Rule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'MY.L6.CHARACTER_SET_SERVER_NOT_UTF8MB4';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'character_set_server';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp(trim($serverValue), $expectation->expectation ?? 'utf8mb4') === 0) {
            return null;
        }

        // utf8mb3 is called out by name rather than lumped in with latin1. It is the trap that looks
        // solved: the name says utf8, it holds most of what anyone tests with, and it silently
        // cannot store anything outside the Basic Multilingual Plane — which is every emoji.
        $problem = match (strcasecmp(trim($serverValue), 'utf8mb3') === 0 || strcasecmp(trim($serverValue), 'utf8') === 0) {
            true => 'the server default character set is utf8mb3, which is three bytes per character and '
                .'cannot store anything outside the Basic Multilingual Plane — every emoji, and a '
                .'good deal of CJK. The name is the trap: it says utf8 and it is not',
            false => sprintf('the server default character set is %s, not %s', $serverValue, $expectation->expectation ?? 'utf8mb4'),
        };

        // The subject of "takes it" is a database, and only a database. "Table Character Set and
        // Collation" gives a table the database default, and "Database Character Set and Collation"
        // gives a database the server one — the chain {@see TextEncoding} documents: column ← table ←
        // database ← server.
        //
        // That is not pedantry. On a utf8mb4 database a latin1 server default is harmless for new
        // tables, so naming tables here would report damage that does not exist and send the reader to
        // audit their tables instead of the one default that decides what the next database gets.
        return sprintf(
            '%s. A DATABASE created without an explicit CHARACTER SET takes it — one made by hand by an '.
            'operator, one a raw-SQL migration creates. Every table created in that database without a '.
            'character set of its own then inherits it in turn, so the level to check is the database '.
            'default rather than each table. On an object that inherited it, a value MySQL cannot '.
            'represent is replaced or truncated rather than refused, depending on the SQL mode. The row '.
            'is stored, altered, and nobody finds out until somebody asks why their name is wrong. Note '.
            'that collation_server follows this setting automatically; changing one changes both. %s',
            $problem,
            $this->remediation($expectation),
        );
    }
}
