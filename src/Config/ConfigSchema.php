<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use BackedEnum;
use Pushery\SQLens\Capture\PreScan\IndirectCallDetector;
use Pushery\SQLens\Capture\PreScan\SideEffectFacadeDetector;
use Pushery\SQLens\Catalog\PrefixScope;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Deploy\Drift\DriftRunMode;
use Pushery\SQLens\Exceptions\UndeclaredConfigPath;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Reporting\Baseline\StaleBaselinePolicy;
use Pushery\SQLens\Reporting\CaptureMode;
use Pushery\SQLens\Reporting\RunProfile;
use Pushery\SQLens\Rules\RuleIdFormat;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\Analyse\AnalyseMode;
use Pushery\SQLens\Severity\Severity;

/**
 * The declarative schema for the `sqlens` config key: which keys exist, what
 * each accepts, and the expectation text a violation reports. This is the ONE
 * owner of the config surface — the suppression, baseline, and reporting layers
 * consume the sections declared here and never re-describe them.
 *
 * Value ranges come from the same enums and parsers the engine runs on
 * (Severity, CaptureMode, RunProfile, Suite, RuleIdFormat, ServerVersion), so
 * the validator can never accept what the engine would reject or vice versa —
 * one source, no drift.
 */
final readonly class ConfigSchema
{
    /**
     * Every key the `sqlens` config array may carry, in the order the shipped
     * config file declares them. All of them ship in the package default, so a
     * merged runtime config is expected to have each one — a missing key means
     * a published copy replaced a section wholesale and dropped it.
     *
     * @var list<string>
     */
    public const array TOP_LEVEL_KEYS = [
        'connection',
        'host',
        'migration_paths',
        'level',
        'categories',
        'stability',
        'mode',
        'profile',
        'strict_tools',
        'strict_undetermined',
        'allow_destructive',
        'use_statistics',
        'assume_server_version',
        'capture',
        'catalog',
        'audit',
        'pgsql',
        'security',
        'preflight',
        'deploy',
        'agent',
        'reporting',
        'baseline',
        'suppression',
        'ignore',
        'profiles',
        'tools',
        'guard',
        'format',
    ];

    /**
     * Sections whose CHILD KEYS are names a project chooses, not names this schema knows.
     *
     * `guard.profiles` holds one entry per profile a project defines, so its keys cannot be listed
     * — but everything INSIDE each entry can be, and must be: the whole point of the guard schema
     * is that a typo in a profile is a configuration error rather than a silently disabled
     * guardrail.
     *
     * The value is the TEMPLATE path each child is validated against. A concrete
     * `guard.profiles.production.strict.throw` is normalized to `guard.profiles.*.strict.throw`
     * before any lookup, so one description and one validator serve every profile a project
     * invents.
     *
     * @var array<string, string>
     */
    public const array WILDCARD_SECTIONS = [
        'guard.profiles' => 'guard.profiles.*',
    ];

    /**
     * The settings a profile may override, as paths into the config above. A
     * profile is a PARTIAL OVERRIDE written in the same shape as the base config,
     * so this list is the only thing profiles add to the vocabulary — no second
     * spelling of a setting that already exists.
     *
     * That is why `strict_undetermined` appears here under its EXISTING name. The
     * plan called the axis `fail_on_undetermined`; adopting that spelling would
     * have created two config keys for one behavior, which is the divergence
     * every other guard in this package exists to prevent.
     *
     * @var list<string>
     */
    public const array PROFILE_OVERRIDABLE = [
        'level',
        'strict_tools',
        'strict_undetermined',
        'use_statistics',
        'assume_server_version',
        'security.min_severity',
    ];

    /**
     * The nested sections and the keys each must carry.
     *
     * @var array<string, list<string>>
     */
    public const array SECTION_KEYS = [
        // A dotted section name declares a NESTED section: `capture` holds `session`,
        // and `capture.session` holds the leaves. The validator walks this
        // recursively, so depth is a data question here rather than a code change.
        'capture' => ['session', 'prescan', 'shadow'],
        'capture.session' => ['statement_timeout', 'lock_timeout'],
        'capture.prescan' => ['side_effects', 'indirect_calls'],
        'capture.prescan.side_effects' => ['additional'],
        'capture.prescan.indirect_calls' => ['allowlist'],
        'capture.shadow' => ['connection', 'direct_connection', 'orphan_after_seconds', 'database_prefix', 'allowed_environments', 'keep_on_failure', 'timeout'],
        'catalog' => ['session', 'budget_ms', 'schemas', 'table_prefix', 'prefix_scope', 'report_partitions_individually', 'include_extension_objects', 'extensions'],
        'catalog.session' => ['statement_timeout', 'lock_timeout', 'idle_in_transaction_timeout', 'application_name'],
        'catalog.extensions' => ['allow'],
        'audit' => ['ignore', 'tenancy', 'uuid_generated_by', 'money_columns', 'unused_index', 'expect', 'naming', 'documentation'],
        'audit.tenancy' => ['mode', 'reference'],
        'audit.ignore' => ['rules', 'objects', 'pairs'],
        'audit.money_columns' => ['extra', 'ignore'],
        'audit.unused_index' => ['min_observation_days'],
        'audit.naming' => ['pattern', 'exempt', 'foreign_key_suffix'],
        'audit.documentation' => ['require_table_comments', 'require_column_comments', 'exempt'],
        'audit.expect' => ['lower_case_table_names'],
        'pgsql' => ['expected_timeouts', 'max_locks_per_transaction'],
        'security' => ['audit_connection', 'min_severity', 'include_vendor_migrations', 'advisories', 'runtime_connection', 'migration_connection', 'analyse', 'rls', 'privacy'],
        'security.rls' => ['mode', 'tables', 'tenant_column'],
        'security.privacy' => ['enabled', 'dictionary', 'extra_terms', 'ignore_columns'],
        'security.analyse' => ['mode', 'result_path'],
        'security.advisories' => ['path', 'source'],
        'preflight' => ['connection', 'budget_ms', 'long_running_ms', 'replication_lag_ms', 'thresholds'],
        'deploy' => ['drift', 'debt', 'predeploy', 'postdeploy'],
        'deploy.postdeploy' => ['budget_ms', 'transition_patterns'],
        'deploy.predeploy' => ['allow_undetermined', 'available_disk_bytes'],
        'deploy.drift' => ['mode', 'exclude_file'],
        'deploy.debt' => ['enabled', 'path', 'thresholds', 'fail_at'],
        'deploy.debt.thresholds' => ['notice', 'warning', 'error'],
        'agent' => ['mcp'],
        'agent.mcp' => ['transport', 'connection', 'findings_path', 'max_findings', 'shadow_consent', 'tools'],
        'agent.mcp.tools' => self::MCP_TOOL_NAMES,
        'reporting' => ['default_format', 'maintenance_window', 'sarif'],
        'reporting.sarif' => ['anchor_file'],
        'baseline' => ['path', 'stale'],
        'suppression' => ['allow_undetermined'],
        'tools' => self::TOOL_NAMES,
        'tools.squawk' => self::TOOL_OPTIONS['squawk'],
        'tools.pgls' => self::TOOL_OPTIONS['pgls'],
        // The guard suite. `profiles` is a WILDCARD section — see self::WILDCARD_SECTIONS — so its
        // own keys are absent here and everything beneath a profile is spelled with the `*`.
        'format' => ['backend', 'dialect', 'binaries', 'timeout', 'style'],
        'format.binaries' => ['pgformatter', 'sqlfluff'],
        'format.style' => ['indent', 'uppercase_keywords', 'leading_commas', 'line_width'],
        'guard' => ['profile', 'profiles'],
        'guard.profiles.*' => ['strict', 'slow_query', 'runtime', 'logging', 'connections'],
        'guard.profiles.*.strict' => ['lazy_loading', 'discarding_attributes', 'missing_attributes', 'destructive_commands', 'throw'],
        'guard.profiles.*.slow_query' => ['enabled', 'threshold_ms', 'cumulative_threshold_ms'],
        'guard.profiles.*.runtime' => ['runtime_ddl', 'unbound_raw_sql'],
        'guard.profiles.*.logging' => ['channel', 'level', 'include_bindings', 'max_sql_length'],
    ];

    /**
     * The keys an `ignore` entry may carry. `rule` and `reason` are mandatory —
     * an ignore without a reason is an undocumented suppression, which is the
     * silent no-op this schema exists to forbid.
     *
     * @var list<string>
     */
    public const array IGNORE_ENTRY_KEYS = ['rule', 'reason', 'paths', 'suites'];

    /** @var list<string> */
    public const array IGNORE_ENTRY_REQUIRED = ['rule', 'reason'];

    /**
     * The legal values of `pgsql.expected_timeouts` — the two client timeout settings the
     * timeout-hygiene rules understand. These are engine names, but they are only strings
     * here: the neutral core imports no driver, so it keeps its own copy rather than reach
     * across the boundary for the driver's authoritative list. A test pins the two lists
     * together (the driver's own KNOWN set against this) so they cannot drift apart.
     *
     * @var list<string>
     */
    public const array PGSQL_TIMEOUT_NAMES = ['lock_timeout', 'statement_timeout'];

    /**
     * The external tools this package knows how to be configured for.
     *
     * A CONFIG contract, not an availability one: a name is listed here because the package
     * understands what to do with it, whether or not the binary exists anywhere. That
     * separation is the point — the configuration states intent, and a project must be able to
     * pin a path on a machine where the tool is not installed yet.
     *
     * It is also what makes a typo an error instead of a no-op. Without a closed set,
     * `sqlens.tools.squauk.path` would be a perfectly valid array that nothing ever reads, and
     * the run would quietly use whatever is on `$PATH` while the configuration looked applied.
     *
     * @var list<string>
     */
    public const array TOOL_NAMES = ['squawk', 'pgls'];

    /**
     * Every tool the MCP server knows how to expose, read-only ones first.
     *
     * A closed set, and for the same reason the external-tool names are one: without it,
     * `agent.mcp.tools.lint_pendign => true` would be a perfectly valid array that nothing reads,
     * and a project would believe it had enabled a tool that does not exist. A typo must be an
     * error naming the real names, never a switch that quietly does nothing.
     *
     * It is also the ONE place a new tool becomes configurable. A tool class that is not named
     * here cannot be turned on by any configuration, which is what keeps the surface from growing
     * by accident.
     *
     * @var list<string>
     */
    public const array MCP_TOOL_NAMES = [
        'lint_pending',
        'explain_rule',
        'get_findings',
        'get_debt_ledger',
        'lint_shadow',
        'predeploy',
    ];

    /**
     * The tools that change something, and therefore ship OFF.
     *
     * `lint_shadow` creates and drops a database; `predeploy` gates a deploy. Listing them here
     * rather than deriving the set from a default value is deliberate: the default is a number in
     * a file a project may edit, and "which tools are dangerous" must not be answerable by editing
     * that file. It is what makes ABSENT mean `false` for these and `true` for the rest — an older
     * project's `tools` map cannot enable one by not mentioning it.
     *
     * @var list<string>
     */
    public const array MCP_MUTATING_TOOLS = ['lint_shadow', 'predeploy'];

    /**
     * The only transport v1 accepts.
     *
     * HTTP is a team-shared endpoint and needs an authentication story of its own; stdio inherits
     * the trust boundary of whatever started the process. The setting exists as a value rather
     * than as an assumption so that the day HTTP arrives, it is a new value here and not a new
     * shape everywhere.
     *
     * @var list<string>
     */
    public const array MCP_TRANSPORTS = ['stdio'];

    /**
     * The formatter backends a project may name.
     *
     * A closed list, checked here rather than at first use: a typo would otherwise be discovered
     * when the formatter refuses, which is after somebody has already committed a run that did
     * nothing.
     */
    public const array FORMAT_BACKENDS = ['auto', 'php', 'pgformatter', 'sqlfluff'];

    /**
     * The PSR-3 levels a guard profile may log at.
     *
     * Checked against a list rather than accepted as any string, for the reason every enum-ish key
     * here is: `warn` is what somebody types, PSR-3 spells it `warning`, and a logger handed the
     * first one throws at the moment a guardrail finally had something to say.
     */
    public const array LOG_LEVELS = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];

    /**
     * The ceiling `agent.mcp.max_findings` may be set to.
     *
     * An upper bound at all, because the setting exists to protect an agent's context window and a
     * value of one million would be the same as having no setting — expressed as a number somebody
     * chose, which is worse than an absent one because it looks deliberate.
     */
    public const int MCP_MAX_FINDINGS_CEILING = 10_000;

    /**
     * The options each tool section carries — PER TOOL, and it did not start that way.
     *
     * This was one shared list, with a note saying a second tool needing different options would
     * be telling us something about the design rather than about itself. The second tool arrived
     * and did exactly that.
     *
     * `fast_path` asks whether a tool may also run in the single-file route, where the budget is
     * under a second. That question exists for a tool that reads a FILE. The Postgres Language
     * Server reads a live database — there is no version of the fast path in which it belongs, so
     * offering the switch would be offering a decision with nothing behind it, and one that could
     * only ever break the sub-second promise the route is built on.
     *
     * So the shape is per-tool now. Three settings are genuinely universal; the fourth is a
     * property of tools that judge documents, which is not all of them.
     *
     * @var array<string, list<string>>
     */
    public const array TOOL_OPTIONS = [
        'squawk' => ['path', 'enabled', 'timeout', 'fast_path'],
        'pgls' => ['path', 'enabled', 'timeout'],
    ];

    /**
     * The one value of `security.min_severity` that is not a severity: report, never block.
     *
     * A named constant because three places have to agree on the spelling — the validator that
     * accepts it, the resolver that turns it into "no floor", and the documentation that tells a
     * reader it exists. A literal in each would be three chances to disagree.
     */
    public const string SEVERITY_GATE_OFF = 'none';

    /**
     * @param  list<string>  $reporterFormats  the formats the reporter manager can
     *                                         resolve; the default mirrors the built-in pair, and the wiring passes the
     *                                         live list so extend()-registered formats validate too
     */
    public function __construct(public array $reporterFormats = ['console', 'json', 'github', 'sarif', 'agent']) {}

    /**
     * Whether the dotted relative path names a key this schema declares — used
     * to tell a literal `'security.min_severity'` top-level key (the Laravel
     * dot-notation trap) apart from a plain typo.
     */
    public function isKnownPath(string $relativePath): bool
    {
        $relativePath = self::template($relativePath);

        if (in_array($relativePath, self::TOP_LEVEL_KEYS, true)) {
            return true;
        }

        foreach (self::SECTION_KEYS as $section => $keys) {
            foreach ($keys as $key) {
                if ($relativePath === $section.'.'.$key) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * A concrete path with its wildcard segment put back, so one entry serves every profile.
     *
     * `guard.profiles.production.strict.throw` becomes `guard.profiles.*.strict.throw`. Anything
     * that is not under a wildcard section comes back untouched, so every other caller is
     * unaffected by the existence of this concept.
     */
    public static function template(string $relativePath): string
    {
        foreach (array_keys(self::WILDCARD_SECTIONS) as $section) {
            if (! str_starts_with($relativePath, $section.'.')) {
                continue;
            }

            $rest = substr($relativePath, strlen($section) + 1);
            $dot = strpos($rest, '.');

            // `false` and `0` are different answers and neither means "no tail": a profile named
            // with a leading dot is not a thing, and `strpos` returning false means the path ends at
            // the profile name. Read as one condition they would collapse.
            return $section.'.*'.($dot === false ? '' : substr($rest, $dot));
        }

        return $relativePath;
    }

    /** The expectation text for a schema path — what a valid value looks like there. */
    public function expectation(string $relativePath): string
    {
        $relativePath = self::template($relativePath);

        // One sentence for every entry of the tool map, for the same reason its validation is one
        // branch: six near-identical arms would be six places to keep one sentence in.
        if (str_starts_with($relativePath, 'agent.mcp.tools.')) {
            $tool = substr($relativePath, strlen('agent.mcp.tools.'));

            return in_array($tool, self::MCP_MUTATING_TOOLS, true)
                ? 'true or false — whether the MCP server exposes `'.$tool.'`. It CHANGES something, so it ships false and is turned on for itself alone; there is no switch that enables the mutating tools together'
                : 'true or false — whether the MCP server exposes `'.$tool.'`. It only reads, and it ships true';
        }

        return match ($relativePath) {
            'connection' => "a database connection name or null (null = the application's default connection)",
            'host' => 'a host name from the connection\'s read list or null (null = decide per run; SQLens refuses to pick when the connection offers several)',
            'migration_paths' => "a list of repo-relative migration paths to lint; empty means the application's registered paths",
            'migration_paths-item' => 'a repo-relative migration path (absolute paths are not portable across machines)',
            'level' => 'an integer between 0 and 9 (the cumulative strictness level)',
            'categories' => 'a list of categories to scope the run to; empty means all',
            'stability' => 'a list of maturity tiers to admit beyond stable; empty means stable only',
            'categories-item' => 'one of: '.$this->enumValues(Category::class),
            // Item specifications, and they are PATHS rather than prose: `listOfStrings()` resolves
            // its last argument through `expectation()`, so an undeclared one throws instead of
            // reporting — which is the opposite of what a config VALIDATOR is for. Measured: three
            // list keys did exactly that, one of them shipped.
            'security.rls.tables-item' => 'a qualified table name (a non-empty string) — for example "public.orders"',
            'security.privacy.extra_terms-item' => 'a term to add to the dictionary (a non-empty string)',
            'security.privacy.ignore_columns-item' => 'a QUALIFIED column name — for example "orders.iban". Unqualified would silence every column with that name, including ones nobody looked at',
            'stability-item' => 'one of: '.$this->enumValues(StabilityTier::class),
            'mode' => 'one of: '.$this->enumValues(CaptureMode::class),
            'profile' => 'one of: '.$this->enumValues(RunProfile::class),
            'strict_tools', 'strict_undetermined' => 'a boolean',
            'allow_destructive' => 'a boolean — whether destructive operations are allowed project-wide (shown as a named suppression, never hidden)',
            'use_statistics' => 'a boolean — whether checks may reason about the server\'s table statistics',
            'assume_server_version' => 'a server version string like "18.0" or "8.4.3", or null (null = no pin)',
            'capture' => 'an array with the keys: session, prescan, shadow',
            'capture.session' => 'an array with the keys: statement_timeout, lock_timeout',
            'catalog' => 'an array with the keys: session, budget_ms, schemas, table_prefix, prefix_scope, report_partitions_individually, include_extension_objects, extensions',
            'catalog.report_partitions_individually' => 'a boolean — whether each partition is reported as its own object instead of being folded onto the table it belongs to',
            'catalog.budget_ms' => 'a positive integer number of milliseconds a whole catalog reading may take before it reports budget_exceeded — zero would mean \'no bound\', which is the harm this setting prevents',
            'catalog.table_prefix' => 'the Laravel table prefix as a string, or null to read it from the connection\'s own prefix setting',
            'catalog.prefix_scope' => 'one of: '.$this->enumValues(PrefixScope::class),
            'catalog.schemas' => 'a list of schemas to audit; empty means the session\'s own resolved scope (search_path on PostgreSQL, the current database on MySQL)',
            'catalog.schemas-item' => 'a schema name as the server spells it (a non-empty string) — for example "tenant_42"',
            'catalog.include_extension_objects' => 'a boolean — whether objects a database extension owns are audited as if the project had written them (PostgreSQL only; MySQL extensions own no catalog objects)',
            'catalog.extensions' => 'an array with the key: allow',
            'catalog.extensions.allow' => 'a list of extension names whose objects ARE audited; empty means none',
            'catalog.extensions.allow-item' => 'an extension name as CREATE EXTENSION spells it (a non-empty string) — for example "citext"',
            'catalog.session' => 'an array with the keys: statement_timeout, lock_timeout, idle_in_transaction_timeout, application_name',
            'catalog.session.statement_timeout', 'catalog.session.lock_timeout', 'catalog.session.idle_in_transaction_timeout' => 'a positive integer number of milliseconds — zero would mean \'wait forever\', which is the harm this setting prevents',
            'catalog.session.application_name' => 'a non-empty string naming the reader session in the server\'s activity view',
            'capture.session.statement_timeout', 'capture.session.lock_timeout' => 'a positive integer number of milliseconds',
            'capture.prescan' => 'an array with the keys: side_effects, indirect_calls',
            'capture.prescan.side_effects' => 'an array with the key: additional',
            'capture.prescan.side_effects.additional' => 'a list of side-effect surfaces to watch in addition to the bundled catalog; empty means none',
            'capture.prescan.side_effects.additional-item' => 'a call target written as Class::method, *::method, function(), Class, or Namespace\\* — for example "App\\Support\\Slack::post"',
            'capture.prescan.indirect_calls' => 'an array with the key: allowlist',
            'capture.prescan.indirect_calls.allowlist' => 'a list of classes an indirect-call hit is not raised for; empty means none',
            'capture.prescan.indirect_calls.allowlist-item' => 'a fully-qualified class name or a namespace prefix written as Namespace\\* — for example "App\\Support\\Formatting" or "App\\ValueObjects\\*"',
            'capture.shadow' => 'an array with the keys: connection, direct_connection, orphan_after_seconds, database_prefix, allowed_environments, keep_on_failure, timeout',
            'capture.shadow.orphan_after_seconds' => 'a whole number of seconds — how old a leaked shadow database must be before a later run removes it. Anything below 3600 is raised to 3600: the age is what stops one parallel worker dropping the throwaway database another is migrating into, and lowering it trades a disk-space annoyance for the one mistake this path must never make',
            'capture.shadow.connection' => 'a database connection name or null (null = the run\'s resolved connection)',
            'capture.shadow.direct_connection' => 'a database connection name to provision through (bypassing a transaction pooler), or null',
            'capture.shadow.database_prefix' => 'a non-empty prefix for the throwaway database name, using only [a-z0-9_]',
            'capture.shadow.allowed_environments' => 'a non-empty list of environment names the shadow mode may run in',
            'capture.shadow.allowed_environments-item' => 'an environment name (a non-empty string)',
            'capture.shadow.keep_on_failure' => 'a boolean — whether to keep the throwaway database when a run fails, for debugging',
            'capture.shadow.timeout' => 'a positive integer number of seconds the shadow provisioning and migration may take',
            'audit' => 'an array with the keys: ignore, tenancy, uuid_generated_by, money_columns, unused_index, expect, naming, documentation',
            'audit.tenancy' => 'an array with the keys: mode, reference',
            'audit.uuid_generated_by' => 'either app or server when the project knows which side generates its UUID primary keys, or null to leave it unanswered',
            'audit.tenancy.mode' => 'either none (one database) or explicit (tenants, and reference names the one to audit)',
            'audit.tenancy.reference' => 'the tenant or connection this report is about, or null when mode is none',
            'audit.ignore' => 'an array with the keys: rules, objects, pairs',
            'audit.ignore.rules' => 'a list of rule ids to silence everywhere; empty means none',
            'audit.ignore.rules-item' => 'a rule id (a non-empty string) — for example "PG.L5.FK_NO_INDEX"',
            'audit.ignore.objects' => 'a list of dotted object paths on which every rule is silenced; empty means none',
            'audit.ignore.objects-item' => 'a dotted object path, optionally ending in * — for example "legacy.*"',
            'audit.ignore.pairs' => 'a list of {rule, objects} entries — the precise form; empty means none',
            'audit.ignore.pairs-item' => 'an entry with a rule id and a non-empty list of object paths',
            'audit.money_columns' => 'an array with the keys: extra, ignore',
            'audit.unused_index' => 'an array with the key: min_observation_days',
            'audit.naming' => 'an array with the keys: pattern, exempt, foreign_key_suffix',
            'audit.naming.pattern' => 'a PCRE pattern an identifier must match, delimiters included — the shipped default is /^[a-z][a-z0-9_]*$/, and a pattern PCRE cannot compile is refused here rather than turning every identifier into a violation',
            'audit.naming.exempt' => 'a list of PCRE patterns naming identifiers this rule does not judge — for a schema somebody else owns, where the convention is not yours to set',
            'audit.naming.foreign_key_suffix' => 'a non-empty string a single-column foreign key\'s column is expected to end with — the default is _id. Empty is refused rather than honored: every name ends with the empty string, so an empty setting silences the rule completely and the project reads "no findings" as "my keys are named the way I asked"',
            'audit.documentation' => 'an array with the keys: require_table_comments, require_column_comments, exempt',
            'audit.documentation.require_table_comments' => 'a boolean — whether a table without a comment is a finding. FALSE by default: level 9 is already an opt-in, and a project that raised its level to see the pedantic band should not be told in the same breath that every table it owns is undocumented',
            'audit.documentation.require_column_comments' => 'a boolean — whether a column without a comment is a finding. Separate from the table switch because it is a different amount of work, and folding the two together would make the cheaper half unreachable',
            'audit.documentation.exempt' => 'a list of bare table names this rule does not judge, or null to use the shipped framework list. It REPLACES that list rather than adding to it, so a project naming its own set is not silently still carrying ours. Names are matched WHOLE: a project\'s own job_applications is not the framework\'s jobs',
            'audit.unused_index.min_observation_days' => 'a whole number of days (0 or more) the statistics must have been running before an unused index is reported',
            'audit.money_columns.extra' => 'a list of column-name terms this project treats as money; empty means the shipped dictionary alone',
            'audit.money_columns.extra-item' => 'a column-name term (a non-empty string) — for example "settlement_amount"',
            'audit.money_columns.ignore' => 'a list of dictionary terms this project does not want reported; empty means none',
            'audit.money_columns.ignore-item' => 'a column-name term (a non-empty string) — for example "rate"',
            'audit.expect' => 'an array with the key: lower_case_table_names',
            'audit.expect.lower_case_table_names' => 'the value this PROJECT expects its servers to run (0, 1 or 2), or null when it has no opinion — SQLens has none of its own, because the right value depends on the deployment',
            'tools' => 'an array with one section per external tool: '.implode(', ', self::TOOL_NAMES),
            'tools.squawk' => 'an array with the keys: '.implode(', ', self::TOOL_OPTIONS['squawk']),
            'tools.pgls' => 'an array with the keys: '.implode(', ', self::TOOL_OPTIONS['pgls']),
            'tools.pgls.path' => 'an absolute path to the postgrestools binary, or null to look on $PATH (a pinned path that does not run is reported, never silently replaced)',
            'tools.pgls.enabled' => 'a boolean — whether this tool may contribute findings; it is a statement of intent, not a promise the binary exists',
            'tools.pgls.timeout' => 'a positive integer number of seconds one invocation may take before it is reported as timed out — this tool opens a connection and reads the catalog, so it needs more of them than a linter that parses text',
            'tools.squawk.path' => 'an absolute path to the squawk binary, or null to look on $PATH (a pinned path that does not run is reported, never silently replaced)',
            'tools.squawk.enabled' => 'a boolean — whether this tool may contribute findings; it is a statement of intent, not a promise the binary exists',
            'tools.squawk.timeout' => 'a positive integer number of seconds one invocation may take before it is reported as timed out',
            'tools.squawk.fast_path' => 'a boolean — whether the tool may also run in the single-file fast path, where the budget is under a second',
            'pgsql' => 'an array with the keys: expected_timeouts, max_locks_per_transaction',
            'pgsql.expected_timeouts' => 'a list of the session timeouts a strong-lock migration must set; empty means neither is required',
            'pgsql.expected_timeouts-item' => 'one of: '.implode(', ', self::PGSQL_TIMEOUT_NAMES),
            'pgsql.max_locks_per_transaction' => 'a positive integer — how many distinct existing tables one migration transaction may strong-lock before it is flagged',
            'security' => 'an array with the keys: audit_connection, min_severity, include_vendor_migrations, advisories, runtime_connection, migration_connection, analyse, rls, privacy',
            'security.audit_connection' => "a connection name from config/database.php for the security readers to RUN ON, or null for the run's own connection. Not to be confused with runtime_connection and migration_connection beside it, which name connections this suite ANALYSES. A name no database config defines is refused rather than fallen back from: falling back would examine a different instance and report it as clean",
            'security.advisories' => 'an array with the keys: path, source',
            'security.advisories.source' => 'an https URL serving a document in this package\'s advisory format, or null — no default ships',
            'security.advisories.path' => 'an absolute path to an end-of-life data file, or null to use the published or bundled copy',
            'security.rls' => 'an array with the keys: mode, tables, tenant_column',
            'security.privacy' => 'an array with the keys: enabled, dictionary, extra_terms, ignore_columns',
            'security.analyse' => 'an array with the keys: mode, result_path',
            'security.analyse.mode' => 'one of: '.AnalyseMode::names().'. `off` is the shipped state and a real answer rather than an omission — the run reports that the injection half examined nothing, instead of returning an empty list that reads as a clean bill of health. `read` takes a result PHPStan has already written',
            'security.analyse.result_path' => 'a path to a PHPStan `--error-format=json` result, repository-relative like every other path here (an absolute one is accepted too), or null when the half is off',
            'security.privacy.enabled' => 'a boolean — whether the privacy rules are registered at all. Off by default: they read column NAMES and guess what lives in them, and a pack that guesses wrong by default teaches a team to ignore the category it guessed in',
            'security.privacy.dictionary' => 'a repository-relative path to a dictionary replacing the bundled one, or null to use the bundled one (absolute is refused: it pins a configuration to one machine)',
            'security.privacy.extra_terms' => 'a list of terms to ADD to whichever dictionary is in force, or an empty list',
            'security.privacy.ignore_columns' => 'a list of QUALIFIED column names this project has looked at and decided about, or an empty list — unqualified would silence a column somebody never considered',
            'security.rls.mode' => "one of: 'listed' (only the tables you name), 'heuristic' (every table carrying the tenant column), 'off'",
            'security.rls.tables' => 'a list of qualified table names, or an empty list',
            'security.rls.tenant_column' => 'a column name, or null when the heuristic is not used',
            'security.runtime_connection' => 'a connection name from config/database.php, or null when the application uses one connection for everything',
            'security.migration_connection' => 'a connection name from config/database.php, or null when the application uses one connection for everything',
            'security.include_vendor_migrations' => 'a boolean: whether a migration shipped inside a package is enumerated by a run, and counted as one of yours when it is',
            'security.min_severity' => 'one of: '.$this->enumValues(Severity::class).", or 'none' (report, never block) — null is refused: say which of the two you mean",
            'preflight' => 'an array with the keys: connection, budget_ms, long_running_ms, replication_lag_ms, thresholds',
            'preflight.long_running_ms' => "a positive integer number of milliseconds a session must have been running before the preflight treats it as something a deploy could collide with — zero is refused rather than read as 'report everything', because a preflight listing every session on a busy server is one nobody reads twice",
            'preflight.replication_lag_ms' => 'a positive integer number of milliseconds of replica lag at which the preflight reports. Measured on the TIME axis (`replay_lag`), which is deliberately not the byte one: a quiet primary keeps the time small however much WAL is outstanding, and both are reported',
            'preflight.thresholds' => 'an array keyed by operation — rewrite, index_build, constraint_validation, backfill — replacing that operation\'s escalation steps entirely. An operation the shipped artefact does not define is REFUSED rather than ignored, because a typo would otherwise mean the escalation somebody configured silently never happens. These numbers only RAISE a severity and can neither create a finding nor remove one: a row estimate depends on when ANALYZE last ran, and a number that could silence a finding would make the same migration pass on Monday and fail on Friday',
            'preflight.budget_ms' => "a positive integer number of milliseconds the WHOLE preflight run may take before the checks it did not reach are reported undetermined — zero would mean 'no bound', and a gate that can delay a deploy indefinitely is the one that gets switched off",
            'preflight.connection' => 'a connection name from config/database.php for the deploy readers to use, or null. Null does NOT fall through to the default connection: that is the one running your migrations, and a preflight reading through it holds ALTER and DROP it never needs',
            'format' => 'an array with the keys: backend, dialect, binaries, timeout, style',
            'format.backend' => 'one of: auto, php, pgformatter, sqlfluff. `auto` picks the best AVAILABLE backend; NAMING one is a promise that it is installed, because a named backend that cannot run is refused rather than silently substituted — a substitution would produce output you did not ask for, and the machine where the binary IS installed would rewrite every file',
            'format.dialect' => 'one of: auto, pgsql, mysql. With `auto` the dialect follows the configured connection',
            'format.binaries' => 'an array with the keys: pgformatter, sqlfluff',
            'format.binaries.pgformatter' => 'an absolute path to the pg_format binary, null to look on the search path, or false to do without this backend entirely. The last is a DECISION rather than a gap: a backend that is merely missing is reported as a loss and fails a strict-tool run, because the machine that has it formats differently and the output is committed — one you switched off is neither',
            'format.binaries.sqlfluff' => 'an absolute path to the sqlfluff binary, null to look on the search path, or false to do without this backend entirely. The last is a DECISION rather than a gap: a backend that is merely missing is reported as a loss and fails a strict-tool run, because the machine that has it formats differently and the output is committed — one you switched off is neither',
            'format.timeout' => 'a positive integer number of seconds one formatter invocation may take. A formatter without a bound holds a CI step, and the shared queue behind it, for as long as it stands',
            'format.style' => 'an array with the keys: indent, uppercase_keywords, leading_commas, line_width',
            'format.style.indent' => 'a positive integer number of spaces per indentation level',
            'format.style.uppercase_keywords' => 'true or false',
            'format.style.leading_commas' => 'true or false — whether a comma leads its line. The one purely aesthetic option here, and it is present because it is the one people argue about',
            'format.style.line_width' => 'a positive integer column past which a single-line statement is broken up',
            'guard' => 'an array with the keys: profile, profiles',
            'guard.profile' => 'the name of the active guard profile, or null. NULL IS OFF — nothing is bound, no listener is registered, and the run reports it as deliberately off rather than as clean. A name this config does not define is an ERROR rather than off: a typo that silently disabled every guardrail is precisely what this key exists to prevent',
            'guard.profiles' => 'a map of profile NAME to profile definition. The names are yours; everything inside one is validated, because a typo in a profile is a guardrail that quietly does nothing',
            'guard.profiles.*' => 'an array with the keys: strict, slow_query, runtime, logging, connections',
            'guard.profiles.*.strict' => 'an array with the keys: lazy_loading, discarding_attributes, missing_attributes, destructive_commands, throw',
            'guard.profiles.*.strict.lazy_loading' => 'true or false — whether Eloquent refuses a lazy load',
            'guard.profiles.*.strict.discarding_attributes' => 'true or false — whether Eloquent refuses to silently discard an attribute that is not fillable',
            'guard.profiles.*.strict.missing_attributes' => 'true or false — whether Eloquent refuses to return null for an attribute that was never retrieved',
            'guard.profiles.*.strict.destructive_commands' => 'true or false — whether Laravel prohibits destructive artisan commands in this environment',
            'guard.profiles.*.strict.throw' => 'true or false — whether a violation also THROWS instead of only being logged. False by default, and that default is primum non nocere: a guardrail that takes an application down in production is worse than the thing it guards against',
            'guard.profiles.*.slow_query' => 'an array with the keys: enabled, threshold_ms, cumulative_threshold_ms',
            'guard.profiles.*.slow_query.enabled' => 'true or false',
            'guard.profiles.*.slow_query.threshold_ms' => 'a positive integer number of milliseconds a SINGLE query may take before it is reported',
            'guard.profiles.*.slow_query.cumulative_threshold_ms' => 'a positive integer number of milliseconds ALL queries in one request may take together before it is reported — the number that catches a hundred fast queries, which no per-query threshold ever will',
            'guard.profiles.*.runtime' => 'an array with the keys: runtime_ddl, unbound_raw_sql',
            'guard.profiles.*.runtime.runtime_ddl' => 'true or false — whether DDL executed at runtime, outside a migration, is reported',
            'guard.profiles.*.runtime.unbound_raw_sql' => 'true or false — whether raw SQL carrying an interpolated value instead of a binding is reported',
            'guard.profiles.*.logging' => 'an array with the keys: channel, level, include_bindings, max_sql_length',
            'guard.profiles.*.logging.channel' => 'a log channel name from config/logging.php, or null for the default channel. A channel this application does not define is an ERROR at boot rather than at the first violation — the alternative is a guardrail that works until the day it has something to say',
            'guard.profiles.*.logging.level' => 'a PSR-3 level: debug, info, notice, warning, error, critical, alert, emergency',
            'guard.profiles.*.logging.include_bindings' => 'true or false — whether query BINDINGS are written to the log. False by default and deliberately: bindings are row data, and a log is the one place row data leaks to somewhere with different access rules',
            'guard.profiles.*.logging.max_sql_length' => 'a positive integer — how many characters of the offending SQL reach the log before it is truncated',
            'guard.profiles.*.connections-item' => 'a connection name that `database.connections` defines',
            'guard.profiles.*.connections' => 'a list of connection names this profile applies to, or an empty list for every connection. A name database.connections does not define is an ERROR: the guardrail would otherwise be silently off for the connection somebody meant',
            'deploy' => 'an array with the keys: drift, debt, predeploy, postdeploy',
            'deploy.postdeploy' => 'an array with the keys: budget_ms, transition_patterns',
            'deploy.postdeploy.budget_ms' => "a positive integer number of milliseconds the WHOLE post-deploy run may take before it reports DEPLOY.RUN.TIME_BUDGET_EXCEEDED — its own number rather than the pre-deploy gate's, because two commands making two promises must not move together, and milliseconds like every other budget here so nobody reads a five-second allowance as five milliseconds",
            'deploy.postdeploy.transition_patterns' => 'a list of PCRE patterns naming objects that look like unfinished-migration leftovers, or null for the shipped list. It REPLACES the shipped one rather than adding to it. A pattern PCRE cannot compile is dropped and a list that ends up empty falls back to the shipped one, because an empty list would silence the check and let a project read "no findings" as "nothing left behind"',
            'deploy.predeploy' => 'an array with the keys: allow_undetermined, available_disk_bytes',
            'deploy.drift' => 'an array with the keys: mode, exclude_file',
            'deploy.drift.exclude_file' => 'a non-empty, repository-relative path — where the differences this project has accepted are recorded. Never null and never absolute: the file is a decision log, and one outside the repository is one nobody reviews. Every entry needs a reason, and an entry that matches nothing ends the run',
            'deploy.drift.mode' => 'one of: report, gate — whether sqlens:drift prints what it found and exits clean, or ends the run with the gate exit code. Report is the shipped state and the one that gets the feature adopted: the first run on a grown production database finds a decade of hand-made objects, and a gate that turns red there is switched off rather than fixed. Raise it after the intentional differences are in the exclude file',
            'deploy.predeploy.available_disk_bytes' => 'a positive integer number of free BYTES on the volume this database writes to, or null to ask the instance. Free filesystem space is not readable from inside a database and never will be on a managed one, so without this the headroom check reports its estimate and stays undetermined. It is a CLAIM rather than a reading — nothing can verify it, and a stale value tells the gate that a full disk is empty, so feed it from the monitoring you would otherwise have checked by hand',
            'deploy.predeploy.allow_undetermined' => "true or false — whether a predeploy blocked ONLY by checks that could not answer still exits clean. False is the shipped state and the safe one: a gate that waves through what it could not read is the silent green this package exists to refuse. Setting it true is the same decision as passing --allow-undetermined on every run, and it is recorded the same way — the report's run header carries undetermined_waiver so a waved-through green can never be mistaken for an earned one",
            'deploy.debt' => 'an array with the keys: enabled, path, thresholds, fail_at',
            'deploy.debt.path' => 'a non-empty, repository-relative path — where the migration debt account file lives. Never null: the ledger is a repo file and always has a location',
            'deploy.debt.enabled' => 'true or false — whether the migration debt account is consulted at all. False is for a project that has not adopted it, never a way to silence a debt: that is what an acknowledged entry with a written reason is for',
            'deploy.debt.fail_at' => 'a whole number of days, one or more, or null — the age at which an outstanding debt breaks a deploy. Null (the default) means never: debts are a reported state, and a command that refused to finish over one would punish the projects using the safe two-step patterns on purpose',
            'deploy.debt.thresholds' => 'an array with the keys: notice, warning, error — the age in UTC calendar days at which an outstanding debt gets louder',
            'deploy.debt.thresholds.notice' => 'a whole number of days, zero or more — when an outstanding debt is worth mentioning',
            'deploy.debt.thresholds.warning' => 'a whole number of days, zero or more — when it has stopped being a plan',
            'deploy.debt.thresholds.error' => 'a whole number of days, zero or more — when the safe half of the safe pattern is not coming',
            'agent' => 'an array with the key: mcp',
            'agent.mcp' => 'an array with the keys: transport, connection, findings_path, max_findings, shadow_consent, tools',
            'agent.mcp.transport' => "the only transport this version speaks: 'stdio'. An HTTP server is a shared endpoint and needs an authentication story of its own, so it is deliberately absent rather than half-built",
            'agent.mcp.connection' => 'a connection name from config/database.php, or null to use the application default — the same connection the CLI would use, because a server answering about a different database would be a second answer nobody asked for',
            'agent.mcp.findings_path' => 'a non-empty, repository-relative path — the report artifact `get_findings` reads. It reads what a previous run wrote and never runs the checks again',
            'agent.mcp.max_findings' => 'a whole number from 1 to '.self::MCP_MAX_FINDINGS_CEILING.' — the most findings one answer may carry, so a large run cannot fill an agent context window with a single tool call. Crossing it is reported, never a quiet truncation',
            'agent.mcp.tools' => 'a map of tool name to true/false, from: '.implode(', ', self::MCP_TOOL_NAMES),
            'agent.mcp.shadow_consent' => 'true or false — the standing "yes, I mean it" a shadow run over the protocol needs. It stands in for the CLI’s --force, because a protocol has nobody to prompt; it never overrides the allowed-environment check and never lets a run reach a production connection',
            'reporting' => 'an array with the keys: default_format, maintenance_window, sarif',
            'reporting.sarif' => 'an array with the keys: anchor_file',
            'reporting.sarif.anchor_file' => 'a non-empty, repository-relative path — the file a live-database alert is anchored to',
            'reporting.default_format' => 'one of: '.implode(', ', $this->reporterFormats),
            'reporting.maintenance_window' => 'true or false — whether a blocking/rewrite finding carries its maintenance-window advice',
            'baseline' => 'an array with the keys: path, stale',
            'baseline.path' => 'a repo-relative file path or null (null = no baseline)',
            'baseline.stale' => 'one of: '.$this->enumValues(StaleBaselinePolicy::class).' — what a baseline entry that matched nothing costs',
            'suppression' => 'an array with the key: allow_undetermined',
            'suppression.allow_undetermined' => 'a list of undetermined reasons a suppression may hide; empty means none',
            'suppression.allow_undetermined-item' => 'one of: '.$this->enumValues(UndeterminedReason::class),
            'ignore' => 'a list of ignore entries, each an array with the keys: rule, reason and optionally paths, suites',
            'ignore-entry' => 'an ignore entry array with the keys: rule, reason and optionally paths, suites',
            'ignore.rule' => 'a rule id matching the documented scheme, like "PG.L2.NAME"',
            'ignore.reason' => 'a non-empty reason string (why this rule is ignored here)',
            'ignore.paths' => 'a list of repo-relative path globs',
            'ignore.paths-item' => 'a repo-relative path glob (absolute paths are not portable across machines)',
            'ignore.suites' => 'a list of suite names',
            'ignore.suites-item' => 'one of: '.$this->enumValues(Suite::class),
            'profiles' => 'an array of environment profiles keyed by: '.$this->enumValues(RunProfile::class).' — each a partial override of the settings above',
            'profile-entry' => 'a partial override array using any of: '.implode(', ', self::PROFILE_OVERRIDABLE).' — written in the same shape as the base config',
            default => throw UndeclaredConfigPath::expectation($relativePath),
        };
    }

    /**
     * Validate a leaf value against its schema path.
     *
     * @return list<ConfigViolation>
     */
    public function leafViolations(string $relativePath, mixed $value): array
    {
        $relativePath = self::template($relativePath);

        $path = 'sqlens.'.$relativePath;
        $expected = $this->expectation($relativePath);

        // Every entry of the tool map answers the same question — is this tool exposed — so it is
        // one branch rather than six `match` arms that would have to be edited in lockstep with
        // MCP_TOOL_NAMES. The names themselves are already closed by the section walk: reaching
        // here means the key IS one of them.
        if (str_starts_with($relativePath, 'agent.mcp.tools.')) {
            return is_bool($value) ? [] : [ConfigViolation::wrongType($path, $expected, $value)];
        }

        return match ($relativePath) {
            // One arm for both: a host is validated in SHAPE here and in MEANING at
            // resolution time, where the connection's own read list is known. Splitting
            // the shape check into a second identical arm would be two places to keep
            // one sentence in.
            'connection', 'host', 'agent.mcp.connection' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [is_string($value)
                    ? ConfigViolation::outOfRange($path, $expected, $value)
                    : ConfigViolation::wrongType($path, $expected, $value)],
            // SHAPE here, MEANING in the loader — the same split the host arm above documents, and
            // for the same reason. Which operation names exist is a fact about the shipped
            // threshold artefact, and `EscalationThresholds::load()` already refuses an unknown one
            // by name. Repeating that list here would be a second authority on it, free to drift
            // toward accepting a name the artefact dropped.
            // An empty array is BOTH a list and the shipped default, so it has to pass; anything
            // else that is a list is a mistake — the steps go one level down, keyed by operation.
            'preflight.thresholds' => is_array($value) && ($value === [] || ! array_is_list($value))
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'level' => is_int($value)
                ? ($value >= 0 && $value <= 9 ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // A typo in a category must be a violation, not a token that silently
            // filters to nothing: a run scoped to a misspelled category would find no
            // rules and read as "clean", the exact false green this refuses.
            'categories' => $this->listOfStrings(
                $path,
                $value,
                'categories',
                static fn (string $item): bool => Category::tryFrom($item) instanceof Category,
                'categories-item',
            ),
            // A typo here would silently admit nothing extra and read as a project that
            // simply never opted in — the same class of silent no-op an unknown category is
            // refused for.
            'stability' => $this->listOfStrings(
                $path,
                $value,
                'stability',
                static fn (string $item): bool => StabilityTier::tryFrom($item) instanceof StabilityTier,
                'stability-item',
            ),
            // Repo-relative paths only, the same portability rule the baseline and
            // ignore paths follow — an absolute path pins the config to one machine.
            'migration_paths' => $this->listOfStrings(
                $path,
                $value,
                'migration_paths',
                fn (string $item): bool => $item !== '' && ! $this->isAbsolutePath($item),
                'migration_paths-item',
            ),
            'mode' => $this->enumLeaf($path, $expected, CaptureMode::class, $value),
            'profile' => $this->enumLeaf($path, $expected, RunProfile::class, $value),
            'strict_tools', 'strict_undetermined', 'use_statistics', 'allow_destructive' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'assume_server_version' => $value === null
                ? []
                : (is_string($value)
                    ? ($value !== '' && ServerVersion::parse($value, 'assumed') instanceof ServerVersion
                        ? []
                        : [ConfigViolation::outOfRange($path, $expected, $value)])
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // A run against a possibly-production connection must never be without a
            // time budget — zero or a negative value would mean "wait forever", which
            // is exactly the harm the session guard exists to prevent.
            'capture.session.statement_timeout', 'capture.session.lock_timeout',
            'catalog.session.statement_timeout', 'catalog.session.lock_timeout',
            'catalog.session.idle_in_transaction_timeout', 'catalog.budget_ms',
            // Same shape, one step further out: this one bounds the whole preflight rather than one
            // reading. It is read by `sqlens:predeploy`, so it has to be declarable — a key the
            // command reads and the validator refuses is a setting nobody can legally use.
            // The same shape for the two preflight THRESHOLDS. They are grouped with the budget on
            // purpose: all three are positive millisecond counts a project may move, and zero is
            // refused on every one of them for the same reason — it would mean "no bound" on the
            // budget and "report everything" on the thresholds, and both produce a gate nobody reads.
            'deploy.postdeploy.budget_ms',
            'preflight.budget_ms', 'preflight.long_running_ms', 'preflight.replication_lag_ms' => is_int($value) && $value > 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // Zero is ALLOWED here, unlike every budget above, and the difference is what the
            // number means. A budget of zero would say "no bound", which is the harm those settings
            // exist to prevent; a threshold of zero says "loud from the first day", which is a
            // legitimate thing for a project to want and the only way to express it.
            // Null is the OFF position and a positive number is a real threshold. Zero is refused
            // rather than read as "break on everything": a project that meant that would be saying
            // every safe two-step pattern must fail its own deploy, which is not a setting anybody
            // wants and is far more likely a typo for null.
            'deploy.debt.fail_at' => $value === null || (is_int($value) && $value > 0)
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'deploy.debt.thresholds.notice',
            'deploy.debt.thresholds.warning',
            'deploy.debt.thresholds.error' => is_int($value) && $value >= 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // The reader identifies itself in the server's activity view. An empty name
            // is refused rather than stored: an unidentified session holding a connection
            // on production is one somebody will eventually kill blind.
            // A blank entry would scope the audit to a schema nobody can name, and the
            // reader would refuse it later with a message about a schema called "". Caught
            // here instead, under the key that produced it.
            // Both lists take the same shape, so they share one arm — and the item spec is derived
            // from the path rather than written twice, which is how the two would drift apart.
            // The two string lists of the audit ignore. `pairs` is not here because its items are
            // arrays rather than strings; it takes the arm below.
            'audit.ignore.rules', 'audit.ignore.objects' => $this->listOfStrings(
                $path,
                $value,
                $relativePath,
                static fn (string $item): bool => trim($item) !== '',
                $relativePath.'-item',
            ),
            // Checked as a LIST only. The shape of each entry — a rule id and a non-empty object
            // list — is enforced where it is read, and duplicating it here would mean two places
            // decide what a pair is. What this arm refuses is the shape that would otherwise reach
            // the reader as something it cannot walk at all.
            'audit.ignore.pairs' => $this->listOfArrays($path, $value, $relativePath),
            // A fixed pair rather than a free string: 'explicit' and 'none' are the whole
            // vocabulary, and a typo that fell through would leave a tenant project running
            // with the guard silently off.
            'audit.tenancy.mode' => in_array($value, ['none', 'explicit'], true)
                ? []
                : [ConfigViolation::outOfRange($path, $this->expectation($relativePath), $value)],
            // Null is a real answer here and the default one: a project that has not decided is
            // better served by an undetermined naming the gap than by a recommendation resting on
            // a guess about code the tool never reads.
            'audit.uuid_generated_by' => $value === null || in_array($value, ['app', 'server'], true)
                ? []
                : [ConfigViolation::outOfRange($path, $this->expectation($relativePath), $value)],
            // Null is the honest value under mode 'none'. Whether a NULL reference is
            // acceptable depends on the mode beside it, and that is a cross-field question
            // the audit runner answers where it has both — a leaf validator that guessed
            // would refuse the shipped default.
            'audit.tenancy.reference' => $value === null || (is_string($value) && trim($value) !== '')
                ? []
                : [ConfigViolation::wrongType($path, $this->expectation($relativePath), $value)],
            'audit.money_columns.extra', 'audit.money_columns.ignore' => $this->listOfStrings(
                $path,
                $value,
                $relativePath,
                static fn (string $item): bool => trim($item) !== '',
                $relativePath.'-item',
            ),
            // Null is "this project has no opinion", and it is the shipped default. There is no
            // sensible package-wide value: 0 is right on Linux, 2 is what macOS installs, and which
            // one a project WANTS is a statement only that project can make. An int cast would be
            // the wrong kindness here — it would turn a typo'd 'two' into a confident 0 and the rule
            // would then report drift against a value nobody chose.
            'audit.expect.lower_case_table_names' => $value === null || (is_int($value) && in_array($value, [0, 1, 2], true))
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'catalog.schemas' => $this->listOfStrings(
                $path,
                $value,
                'catalog.schemas',
                static fn (string $item): bool => trim($item) !== '',
                'catalog.schemas-item',
            ),
            // Null is the ordinary "not configured" — the override exists for setups that
            // set the prefix at runtime, so leaving it unset is the normal state and must
            // not read as a prefix of '' that somebody chose.
            'catalog.table_prefix' => $value === null || is_string($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'catalog.prefix_scope' => is_string($value) && PrefixScope::tryFrom($value) instanceof PrefixScope
                ? []
                : (is_string($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'catalog.include_extension_objects', 'catalog.report_partitions_individually' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // An extension named here is one whose objects the project takes
            // responsibility for. An empty entry would silently allow nothing, which
            // reads like an allowance that works.
            'catalog.extensions.allow' => $this->listOfStrings(
                $path,
                $value,
                'catalog.extensions.allow',
                static fn (string $item): bool => trim($item) !== '',
                'catalog.extensions.allow-item',
            ),
            'catalog.session.application_name' => is_string($value) && trim($value) !== ''
                ? []
                : (is_string($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // A typo here must be a violation, not an entry that silently watches
            // nothing: a project that added a surface and got no finding would read
            // the silence as "we are clean", which is the exact inversion of what
            // adding the entry was for.
            'capture.prescan.side_effects.additional' => $this->listOfStrings(
                $path,
                $value,
                'capture.prescan.side_effects.additional',
                static fn (string $item): bool => SideEffectFacadeDetector::acceptsTarget($item),
                'capture.prescan.side_effects.additional-item',
            ),
            // A class or namespace prefix, the same grammar the indirect-call
            // exemptions use — validated so a typo cannot silently fail to widen
            // the allowlist and leave a project flagged for a class it exempted.
            'capture.prescan.indirect_calls.allowlist' => $this->listOfStrings(
                $path,
                $value,
                'capture.prescan.indirect_calls.allowlist',
                static fn (string $item): bool => IndirectCallDetector::acceptsAllowlistEntry($item),
                'capture.prescan.indirect_calls.allowlist-item',
            ),
            'capture.shadow.connection', 'capture.shadow.direct_connection' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [is_string($value)
                    ? ConfigViolation::outOfRange($path, $expected, $value)
                    : ConfigViolation::wrongType($path, $expected, $value)],
            'capture.shadow.database_prefix' => is_string($value)
                ? ($value !== '' && preg_match('/^[a-z0-9_]+$/', $value) === 1 ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'capture.shadow.allowed_environments' => $this->listOfStrings(
                $path,
                $value,
                'capture.shadow.allowed_environments',
                static fn (string $item): bool => $item !== '',
                'capture.shadow.allowed_environments-item',
                requireNonEmpty: true,
            ),
            'capture.shadow.keep_on_failure' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // A time budget for a mode that creates and drops a database: zero or a
            // negative value is refused, not normalized, exactly like the session
            // budgets — an unbounded shadow run is the harm the timeout prevents.
            // A pinned path or none. An empty string is rejected rather than treated as "no
            // path": it is what a half-filled environment variable interpolates to, and reading
            // it as "look on \$PATH" would turn a broken deployment into a silent fallback.
            'tools.squawk.path', 'tools.pgls.path' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [is_string($value)
                    ? ConfigViolation::outOfRange($path, $expected, $value)
                    : ConfigViolation::wrongType($path, $expected, $value)],
            'tools.squawk.enabled', 'tools.squawk.fast_path', 'tools.pgls.enabled' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Zero would mean "wait forever", which is the harm a bound exists to prevent — the
            // same reading every other timeout in this schema gets.
            'tools.squawk.timeout', 'tools.pgls.timeout' => is_int($value) && $value > 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // A whole number of seconds. The FLOOR is applied where the value is read rather than
            // rejected here: a project that wrote 60 meant "sweep sooner", and refusing its config
            // outright would be a worse answer than quietly giving it the safe minimum — which the
            // config comment beside the key states plainly.
            'capture.shadow.orphan_after_seconds' => is_int($value) && $value > 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'capture.shadow.timeout' => is_int($value) && $value > 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // A typo here must abort, not silently disable a timeout rule: a project that
            // wrote 'lock_timout' and saw no MISSING_LOCK_TIMEOUT finding would read the
            // silence as "we set our timeouts", the exact false green this refuses.
            'pgsql.expected_timeouts' => $this->listOfStrings(
                $path,
                $value,
                'pgsql.expected_timeouts',
                static fn (string $item): bool => in_array($item, self::PGSQL_TIMEOUT_NAMES, true),
                'pgsql.expected_timeouts-item',
            ),
            // A threshold below 1 would mean "flag a transaction that locks zero tables",
            // which is never a finding — a misconfiguration, not a normalized zero.
            // Zero IS meaningful here, unlike the lock threshold below: it means "report on
            // whatever window the server has", which is the honest setting for a project that
            // knows its statistics have never been reset. A negative value is not a shorter
            // window, it is a mistake.
            // A pattern PCRE cannot compile is REFUSED, and that is the whole reason this leaf has a
            // check of its own. `preg_match()` answers `false` for a broken pattern rather than `0`,
            // and `false !== 1` — so one typo in a project's pattern would turn every identifier in
            // the database into a violation, with nothing in the report pointing at the setting.
            // Measured with `/^[a-z/`: `violates('orders')` came back true, and `orders` is the
            // canonical GOOD name in this rule's own default.
            //
            // The silence operator is the narrow kind: the only diagnostic `preg_match()` raises
            // here is about the pattern, and it is not swallowed — its failure IS the violation.
            'audit.naming.pattern' => is_string($value) && @preg_match($value, '') !== false
                ? []
                : (is_string($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'audit.naming.exempt' => is_array($value) && array_all($value, static fn (mixed $entry): bool => is_string($entry) && @preg_match($entry, '') !== false)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // The EMPTYING value is refused rather than normalized: every name ends with the empty
            // string, so an empty suffix silences the rule completely — and the project reads "no
            // findings" as "my keys are named the way I asked" when nothing had been asked.
            'audit.naming.foreign_key_suffix' => is_string($value) && $value !== ''
                ? []
                : [is_string($value) ? ConfigViolation::outOfRange($path, $expected, $value) : ConfigViolation::wrongType($path, $expected, $value)],
            'audit.unused_index.min_observation_days' => is_int($value) && $value >= 0
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'audit.documentation.require_table_comments', 'audit.documentation.require_column_comments' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Null is the shipped default and means "use the framework list". A list REPLACES it.
            // Refused as anything else rather than coerced: a string here would exempt one table
            // and read as though it exempted a set.
            'audit.documentation.exempt' => $value === null || (is_array($value) && array_all($value, static fn (mixed $entry): bool => is_string($entry) && $entry !== ''))
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Null is the shipped default and means "use the list this package ships". A list
            // REPLACES it. Each entry must be a pattern PCRE can compile — refused here rather than
            // dropped at runtime, because a project that wrote a broken pattern deserves to be told
            // so once rather than to read a quiet "no findings" forever.
            'deploy.postdeploy.transition_patterns' => $value === null || (is_array($value) && array_all($value, static fn (mixed $entry): bool => is_string($entry) && $entry !== '' && @preg_match($entry, '') !== false))
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'pgsql.max_locks_per_transaction' => is_int($value) && $value >= 1
                ? []
                : (is_int($value)
                    ? [ConfigViolation::outOfRange($path, $expected, $value)]
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // `none` is a legal VALUE, not the absence of one — and null is refused rather than read
            // as "off". A key left null reads as unset, so a project could not tell its own future
            // reader whether the gate was switched off on purpose or the line was never finished.
            // Refusing it costs one migration step and removes the ambiguity permanently.
            // Null is legal here and MEANS something: the project runs everything on one connection.
            // That is the state the least-privilege rule reports on, so refusing null would force a
            // project to invent an answer to a question it is entitled to leave open.
            // The preflight connection joins them, and null means the same thing in all three: a
            // question the project is entitled to leave open. What differs is what null COSTS here
            // — the reading stops with a named reason rather than borrowing the migration
            // connection, so leaving it open is a decision rather than a default.
            'security.audit_connection', 'security.runtime_connection', 'security.migration_connection', 'preflight.connection' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'security.rls.mode' => is_string($value) && in_array($value, ['listed', 'heuristic', 'off'], true)
                ? []
                : [ConfigViolation::outOfRange($path, $expected, $value)],
            // Read off the enum rather than repeated as a literal list. A second copy would go stale
            // the day a mode is added, and it would go stale QUIETLY — the config would refuse a
            // value the code accepts, which reads to a user as their own typo.
            'security.analyse.mode' => is_string($value) && AnalyseMode::tryFrom($value) instanceof AnalyseMode
                ? []
                : [ConfigViolation::outOfRange($path, $expected, $value)],
            'security.analyse.result_path' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'security.rls.tables' => $this->listOfStrings(
                $path,
                $value,
                'security.rls.tables',
                static fn (string $item): bool => trim($item) !== '',
                'security.rls.tables-item',
            ),
            'security.rls.tenant_column' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'security.privacy.enabled' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Repository-relative, and an empty string is refused rather than read as "no path":
            // it is what a half-filled environment variable interpolates to, and reading it as
            // "use the bundled one" would turn a broken deployment into a silent fallback.
            'security.privacy.dictionary' => $value === null || (is_string($value) && $value !== '' && ! str_starts_with($value, '/'))
                ? []
                : [is_string($value)
                    ? ConfigViolation::outOfRange($path, $expected, $value)
                    : ConfigViolation::wrongType($path, $expected, $value)],
            'security.privacy.extra_terms' => $this->listOfStrings(
                $path,
                $value,
                'security.privacy.extra_terms',
                static fn (string $item): bool => trim($item) !== '',
                'security.privacy.extra_terms-item',
            ),
            // Qualified, and the dot is what makes it so. `notes` is a different question on
            // `orders` than on `patients`, so an unqualified entry would silence a column somebody
            // never considered — the one way an ignore list can hide a finding nobody decided about.
            'security.privacy.ignore_columns' => $this->listOfStrings(
                $path,
                $value,
                'security.privacy.ignore_columns',
                static fn (string $item): bool => str_contains(trim($item), '.'),
                'security.privacy.ignore_columns-item',
            ),
            'security.min_severity' => $value === self::SEVERITY_GATE_OFF
                ? []
                : $this->enumLeaf($path, $expected, Severity::class, $value),
            // Validated against the enum rather than a pair of string literals, so the day a third
            // mode arrives this arm does not change — and a typo lands as an out-of-range value
            // naming the key rather than silently becoming `report`.
            // The same shape as `deploy.debt.path`, and for the same reason: both are decision logs
            // that live in the repository. Absolute is refused rather than honored — a decision log
            // outside the tree is one whose changes nobody reviews, and null would leave the run to
            // guess where a project keeps its own record.
            'deploy.drift.exclude_file' => is_string($value) && $value !== '' && ! $this->isAbsolutePath($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'deploy.drift.mode' => $this->enumLeaf($path, $expected, DriftRunMode::class, $value),
            'reporting.default_format' => is_string($value)
                ? (in_array($value, $this->reporterFormats, true) ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'format.backend' => is_string($value) && in_array($value, self::FORMAT_BACKENDS, true)
                ? []
                : [ConfigViolation::outOfRange($path, $expected, $value)],
            'format.dialect' => is_string($value) && in_array($value, ['auto', 'pgsql', 'mysql'], true)
                ? []
                : [ConfigViolation::outOfRange($path, $expected, $value)],
            // Three-valued, and the third is the one the other two cannot say: `false` means this
            // project decided to do without the backend. `null` has meant "look on the search path"
            // since this block existed and keeps meaning it — reading a falsy null as a decision
            // would turn every default installation into one that switched both backends off.
            'format.binaries.pgformatter',
            'format.binaries.sqlfluff' => $value === null || $value === false || (is_string($value) && $value !== '')
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'format.timeout',
            'format.style.indent',
            'format.style.line_width' => is_int($value) && $value > 0
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'format.style.uppercase_keywords',
            'format.style.leading_commas' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Every guard boolean in one arm. They are the same shape and the same question, and
            // five near-identical arms would be five places for one of them to drift.
            'guard.profiles.*.strict.lazy_loading',
            'guard.profiles.*.strict.discarding_attributes',
            'guard.profiles.*.strict.missing_attributes',
            'guard.profiles.*.strict.destructive_commands',
            'guard.profiles.*.strict.throw',
            'guard.profiles.*.slow_query.enabled',
            'guard.profiles.*.runtime.runtime_ddl',
            'guard.profiles.*.runtime.unbound_raw_sql',
            'guard.profiles.*.logging.include_bindings' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // The three positive integers. Zero is refused rather than read as "no bound": a
            // threshold of zero would report every query ever run, and a truncation length of zero
            // would log the empty string — both are an unset value spelled wrongly.
            'guard.profiles.*.slow_query.threshold_ms',
            'guard.profiles.*.slow_query.cumulative_threshold_ms',
            'guard.profiles.*.logging.max_sql_length' => is_int($value) && $value > 0
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'guard.profiles.*.logging.level' => is_string($value) && in_array($value, self::LOG_LEVELS, true)
                ? []
                : [ConfigViolation::outOfRange($path, $expected, $value)],
            'guard.profile',
            'guard.profiles.*.logging.channel' => $value === null || (is_string($value) && $value !== '')
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'guard.profiles.*.connections' => $this->listOfStrings(
                $path,
                $value,
                'guard.profiles.*.connections',
                static fn (string $item): bool => $item !== '',
                'guard.profiles.*.connections-item',
            ),
            // Its own arm, and NOT folded into the boolean group below: a positive integer or null
            // is a different shape, and a case slipped into a grouped arm changes what its
            // neighbors return. That is exactly what a first draft of this line did.
            'deploy.predeploy.available_disk_bytes' => $value === null || (is_int($value) && $value > 0)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'deploy.debt.enabled',
            'deploy.predeploy.allow_undetermined',
            'security.include_vendor_migrations',
            'reporting.maintenance_window' => is_bool($value) ? [] : [ConfigViolation::wrongType($path, $expected, $value)],
            // Exactly one legal value today, and it is still checked against a list rather than a
            // string literal: the day HTTP arrives, this arm does not change.
            'agent.mcp.transport' => is_string($value)
                ? (in_array($value, self::MCP_TRANSPORTS, true) ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Bounded on BOTH sides. Zero would mean "answer with nothing", which is not a smaller
            // answer but a silent one; a value without a ceiling would be the same as having no
            // setting, only written down so it looks deliberate.
            // The standing consent a protocol needs, because it cannot be asked. It is the WEAKEST
            // of the guard's three checks that it can answer — the allowed-environment list and the
            // production-connection detector still refuse, and neither is overridable — so what it
            // grants is a confirmation inside an environment somebody already restricted.
            'agent.mcp.shadow_consent' => is_bool($value)
                ? []
                : [ConfigViolation::wrongType($path, $expected, $value)],
            'agent.mcp.max_findings' => is_int($value)
                ? ($value >= 1 && $value <= self::MCP_MAX_FINDINGS_CEILING ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Repository-relative, and the refusal of an absolute path is not pedantry: the URI goes
            // into a report GitHub resolves against the repository, so `/Users/someone/app/config`
            // matches nothing there and the alert loses the anchor it was given.
            'reporting.sarif.anchor_file' => is_string($value) && trim($value) !== ''
                ? ($this->isAbsolutePath($value) ? [ConfigViolation::outOfRange($path, $expected, $value)] : [])
                : [ConfigViolation::wrongType($path, $expected, $value)],
            // Absolute, deliberately, and the opposite of `baseline.path` one line down. A baseline
            // lives IN the repository and is compared across machines, so a repo-relative path is
            // the only portable one. An advisory file is an operational artifact that a refresh may
            // write outside the tree entirely — a cache directory, a mounted volume — and forcing it
            // repo-relative would push a generated file into version control.
            // https only, and null by default. A refresh that would fetch over plain http could be
            // answered by anybody on the path with a file this package then trusts as its security
            // baseline — the one artifact where being lied to is worst.
            'security.advisories.source' => $value === null
                ? []
                : (is_string($value)
                    ? (str_starts_with($value, 'https://') ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'security.advisories.path' => $value === null
                ? []
                : (is_string($value)
                    ? ($value !== '' && $this->isAbsolutePath($value) ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            // Repository-relative and never null, the opposite of `baseline.path` below. A project
            // may genuinely have no baseline; it always has somewhere the debt account would live,
            // so null here would only be a second spelling of "record nothing" -- which an empty
            // ledger already says, out loud and in the file a reviewer can see.
            'deploy.debt.path' => is_string($value) && $value !== '' && ! $this->isAbsolutePath($value)
                ? []
                : (is_string($value) ? [ConfigViolation::outOfRange($path, $expected, $value)] : [ConfigViolation::wrongType($path, $expected, $value)]),
            // Repository-relative for the same reason the debt account's path is: the artifact
            // lives IN the repository, and an absolute path pins the configuration to one machine.
            'agent.mcp.findings_path' => is_string($value) && $value !== '' && ! $this->isAbsolutePath($value)
                ? []
                : (is_string($value) ? [ConfigViolation::outOfRange($path, $expected, $value)] : [ConfigViolation::wrongType($path, $expected, $value)]),
            'baseline.path' => $value === null
                ? []
                : (is_string($value)
                    ? ($value !== '' && ! $this->isAbsolutePath($value) ? [] : [ConfigViolation::outOfRange($path, $expected, $value)])
                    : [ConfigViolation::wrongType($path, $expected, $value)]),
            'baseline.stale' => $this->enumLeaf($path, $expected, StaleBaselinePolicy::class, $value),
            'suppression.allow_undetermined' => $this->listOfStrings(
                $path,
                $value,
                'suppression.allow_undetermined',
                static fn (string $item): bool => UndeterminedReason::tryFrom($item) instanceof UndeterminedReason,
                'suppression.allow_undetermined-item',
            ),
            default => throw UndeclaredConfigPath::notALeaf($relativePath),
        };
    }

    /**
     * The profile names SQLens knows — the enum's own cases, so a profile the run
     * header can report is exactly a profile the config may declare.
     *
     * @return list<string>
     */
    public function profileNames(): array
    {
        return array_map(static fn (RunProfile $profile): string => $profile->value, RunProfile::cases());
    }

    /**
     * Validate one field of an `ignore` entry. `$path` is the absolute dotted
     * path of the field (e.g. `sqlens.ignore.0.rule`) so a violation names the
     * exact entry, not just "somewhere in ignore".
     *
     * @return list<ConfigViolation>
     */
    public function ignoreFieldViolations(string $path, string $field, mixed $value): array
    {
        return match ($field) {
            'rule' => is_string($value)
                ? (RuleIdFormat::matches($value) ? [] : [ConfigViolation::outOfRange($path, $this->expectation('ignore.rule'), $value)])
                : [ConfigViolation::wrongType($path, $this->expectation('ignore.rule'), $value)],
            'reason' => is_string($value)
                ? ($value !== '' ? [] : [ConfigViolation::outOfRange($path, $this->expectation('ignore.reason'), $value)])
                : [ConfigViolation::wrongType($path, $this->expectation('ignore.reason'), $value)],
            'paths' => $this->listOfStrings($path, $value, 'ignore.paths', fn (string $item): bool => $item !== '' && ! $this->isAbsolutePath($item), 'ignore.paths-item'),
            'suites' => $this->listOfStrings($path, $value, 'ignore.suites', fn (string $item): bool => Suite::tryFrom($item) instanceof Suite, 'ignore.suites-item'),
            default => throw UndeclaredConfigPath::notAnIgnoreField($field),
        };
    }

    /**
     * Validate a list-of-strings field: it must be a list, and every item must be
     * a string the given check accepts. Every bad item is reported, not just the
     * first — a fix-rerun loop is the thing this validator exists to avoid.
     *
     * @param  callable(string): bool  $itemIsValid
     * @return list<ConfigViolation>
     */
    private function listOfStrings(string $path, mixed $value, string $fieldSpec, callable $itemIsValid, string $itemSpec, bool $requireNonEmpty = false): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [ConfigViolation::wrongType($path, $this->expectation($fieldSpec), $value)];
        }

        // Some lists are meaningless empty: an empty allowed-environments list would
        // let the shadow mode run nowhere, which is a misconfiguration, not "none".
        if ($requireNonEmpty && $value === []) {
            return [ConfigViolation::outOfRange($path, $this->expectation($fieldSpec), $value)];
        }

        $violations = [];

        foreach ($value as $index => $item) {
            if (! is_string($item)) {
                $violations[] = ConfigViolation::wrongType($path.'.'.$index, $this->expectation($itemSpec), $item);
            } elseif (! $itemIsValid($item)) {
                $violations[] = ConfigViolation::outOfRange($path.'.'.$index, $this->expectation($itemSpec), $item);
            }
        }

        return $violations;
    }

    /**
     * Validate a list whose items are themselves arrays — the ignore list's `pairs` form.
     *
     * Deliberately shallow. What each entry CONTAINS is decided where it is read, and repeating
     * that here would put the definition of a pair in two places, which is how the two come to
     * disagree. What this refuses is the shape nothing downstream can walk at all: a scalar where
     * a list belongs, or an entry that is not an array.
     *
     * @return list<ConfigViolation>
     */
    private function listOfArrays(string $path, mixed $value, string $fieldSpec): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [ConfigViolation::wrongType($path, $this->expectation($fieldSpec), $value)];
        }

        $violations = [];

        foreach ($value as $index => $item) {
            if (! is_array($item)) {
                $violations[] = ConfigViolation::wrongType($path.'.'.$index, $this->expectation($fieldSpec.'-item'), $item);
            }
        }

        return $violations;
    }

    /**
     * Validate a string-backed-enum leaf: a non-string is a wrong type, a string
     * outside the enum's values is out of range.
     *
     * @param  class-string<BackedEnum>  $enum
     * @return list<ConfigViolation>
     */
    private function enumLeaf(string $path, string $expected, string $enum, mixed $value): array
    {
        if (! is_string($value)) {
            return [ConfigViolation::wrongType($path, $expected, $value)];
        }

        return $enum::tryFrom($value) instanceof BackedEnum
            ? []
            : [ConfigViolation::outOfRange($path, $expected, $value)];
    }

    /**
     * The comma-separated backed values of an enum — expectation texts list the
     * legal values from the enum itself, so a new case is announced automatically.
     *
     * @param  class-string<BackedEnum>  $enum
     */
    private function enumValues(string $enum): string
    {
        return implode(', ', array_map(fn (BackedEnum $case): string => (string) $case->value, $enum::cases()));
    }

    /**
     * Unix, Windows drive, or UNC absolute — all rejected where the schema wants
     * repo-relative, because an absolute path pins the config to one machine.
     */
    private function isAbsolutePath(string $path): bool
    {
        return preg_match('#^(?:/|\\\\|[A-Za-z]:[/\\\\])#', $path) === 1;
    }
}
