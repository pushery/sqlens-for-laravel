<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Filesystem\Filesystem;
use Pushery\SQLens\Contracts\MetadataRenderer;
use Pushery\SQLens\Generation\ActiveRuleResolver;
use Pushery\SQLens\Generation\AgentContextFormat;
use Pushery\SQLens\Generation\ArtifactFamily;
use Pushery\SQLens\Generation\ArtifactWriting;
use Pushery\SQLens\Generation\GeneratedArtifact;
use Pushery\SQLens\Generation\MarkerBlock;
use Pushery\SQLens\Generation\MarkerBlockWriter;
use Pushery\SQLens\Generation\MetadataExporter;
use Pushery\SQLens\Generation\Renderers\ClaudeMarkdownRenderer;
use Pushery\SQLens\Generation\Renderers\CopilotInstructionsRenderer;
use Pushery\SQLens\Generation\Renderers\CursorRulesRenderer;
use Pushery\SQLens\Generation\RuleCatalogSnapshot;
use Pushery\SQLens\Generation\UnregisterableRenderer;
use Pushery\SQLens\Generation\UnresolvableRuleCatalog;
use Pushery\SQLens\Reporting\Agent\Redactor;
use Pushery\SQLens\ShippedLocale;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `sqlens:agent-rules` — write the project's ACTIVE rule set into its coding agents' context files,
 * so an agent knows the rule before it writes the migration rather than after the linter rejects it.
 *
 * ## What it touches, and what it cannot
 *
 * Repository files, and nothing else. No database is opened — this works on rule metadata and
 * configuration, so it runs in a fresh clone, in a CI image, and offline. A missing connection is
 * therefore not a reason for an undetermined result; there was never a question to leave open.
 *
 * ## `--check` and writing are one path
 *
 * The artifacts are produced identically either way; the only difference is whether the bytes reach
 * the disk. That is why the exporter is handed no filesystem and the writer returns content instead
 * of writing it — two paths for "check" and "write" would agree until they did not, and the
 * disagreement would be found by somebody whose green `--check` was wrong.
 *
 * ## The case `--check` exists for is the MISSING file
 *
 * It is the commonest state in a consuming project's CI — a fresh clone, or a target nobody ever
 * generated — and the easiest to answer wrongly, because the write path would simply create it. A
 * missing file and a file without the marked block are both DEVIATIONS, and in both cases nothing
 * is written. A `--check` that quietly created what it was asked to verify would make the
 * consistency promise worthless exactly where it is supposed to hold.
 *
 * ## `--target=all` means all AGENT targets
 *
 * It iterates the `agent_rules` family, never "everything registered". Other families exist on the
 * same registry and write elsewhere; `all` picking them up would put this package's own artifacts
 * into somebody else's repository.
 */
final class AgentRulesCommand extends Command
{
    /**
     * The generator's own version, carried into every marker line and generated-file notice.
     *
     * Bumped when the ARTIFACT SHAPE changes, not when the rules do — the catalog hash beside it
     * already answers "did the rules move", and two fields answering one question is how they end
     * up disagreeing.
     */
    public const string GENERATOR_VERSION = '1';

    /** @var string */
    protected $signature = 'sqlens:agent-rules
        {--connection= : The connection whose engine to describe; defaults to the resolved sqlens/default connection}
        {--target=all : Which agent context to write — claude, cursor, copilot, or all}
        {--output= : Write the artifact to this path instead of the target’s default; only with a single --target}
        {--check : Report whether every artifact is current, write nothing, and exit non-zero on a deviation}
        {--dry-run : Print what would be written without touching a file}';

    /** @var string */
    protected $description = 'Write the active rule set into this project’s coding-agent context files';

    public function handle(
        ActiveRuleResolver $resolver,
        MarkerBlockWriter $markers,
        Filesystem $files,
        Translator $translator,
        Application $app,
        Redactor $redactor,
    ): int {
        $targets = $this->targets();

        if ($targets === null) {
            $this->stderr()->writeln($this->translate($translator, 'agent_rules_unknown_target', [
                'target' => (string) $this->option('target'),
                'known' => 'claude, cursor, copilot, all',
            ]));

            return ExitCode::Misconfiguration->value;
        }

        $override = $this->overridePath();

        if ($override !== null && count($targets) > 1) {
            // One path cannot hold three artifacts, and picking one silently would write two of
            // them nowhere. Named, because the person who typed it meant something specific.
            $this->stderr()->writeln($this->translate($translator, 'agent_rules_output_needs_one_target'));

            return ExitCode::Misconfiguration->value;
        }

        try {
            $snapshot = $resolver->resolve(connection: $this->connection());
            $artifacts = $this->exporterFor($targets, $redactor)->export($snapshot, ArtifactFamily::AgentRules);
        } catch (UnresolvableRuleCatalog|UnregisterableRenderer $refusal) {
            // Translated when the refusal carries a key, and the English message otherwise. Not a
            // fallback that hides a gap: a refusal without a key has not been localized yet, and
            // printing its English sentence is better than printing an unresolved key at somebody.
            $this->stderr()->writeln(
                $refusal instanceof UnresolvableRuleCatalog && $refusal->translationKey !== null
                    ? $this->translate($translator, $refusal->translationKey, $refusal->replacements ?? [])
                    : $refusal->getMessage(),
            );

            return ExitCode::Misconfiguration->value;
        }

        $note = $snapshot->context->versionNote();

        if ($note !== null) {
            // Named rather than silent, and on stderr so a piped `--dry-run` stays the artifact.
            $this->stderr()->writeln($note);
        }

        return $this->deliver($artifacts, $snapshot, $override, $markers, $files, $translator, $app->basePath());
    }

    /**
     * Write, check or print — the one branch, at the end, over identical content.
     *
     * @param  list<GeneratedArtifact>  $artifacts
     */
    private function deliver(
        array $artifacts,
        RuleCatalogSnapshot $snapshot,
        ?string $override,
        MarkerBlockWriter $markers,
        Filesystem $files,
        Translator $translator,
        string $root,
    ): int {
        $check = $this->option('check') === true;
        $dryRun = $this->option('dry-run') === true;
        $deviations = 0;

        foreach ($artifacts as $artifact) {
            $relative = $override ?? $artifact->path;
            $absolute = $root.'/'.ltrim($relative, '/');
            $existing = $files->exists($absolute) ? (string) $files->get($absolute) : null;
            $desired = $this->desiredContent($artifact, $snapshot, $existing, $markers);

            if ($dryRun) {
                $this->line($desired);

                continue;
            }

            if ($check) {
                if ($desired !== $existing) {
                    $deviations++;
                    $this->stderr()->writeln($this->translate($translator, $existing === null
                        ? 'agent_rules_check_missing'
                        : 'agent_rules_check_stale', ['path' => $relative]));
                }

                continue;
            }

            ArtifactWriting::write($files, $absolute, $desired);
            $this->line($this->translate($translator, 'agent_rules_written', ['path' => $relative]));
        }

        if ($check) {
            // Distinguishable from a misconfiguration on purpose: a stale artifact is a real
            // finding about the project, not a broken invocation, and a CI job wants to tell them
            // apart without reading the message.
            return $deviations === 0
                ? $this->reportCurrent($translator, count($artifacts))
                : ExitCode::FindingsAboveGate->value;
        }

        return ExitCode::Clean->value;
    }

    /**
     * The complete bytes a target's file should hold.
     *
     * A whole-file target is its content. A marked-region target is that content placed into
     * whatever is already there — which is where the neighbor's own text survives, and why the
     * missing-file case still produces a full answer to compare against rather than a special case.
     */
    private function desiredContent(
        GeneratedArtifact $artifact,
        RuleCatalogSnapshot $snapshot,
        ?string $existing,
        MarkerBlockWriter $markers,
    ): string {
        if (! $artifact->isMarkedRegion()) {
            return $artifact->content;
        }

        return $markers->apply(
            $existing,
            MarkerBlock::agentRules(self::GENERATOR_VERSION, $snapshot->hash()),
            $artifact->content,
        );
    }

    /** The clean `--check` result, said out loud rather than left as an empty success. */
    private function reportCurrent(Translator $translator, int $count): int
    {
        $this->line($this->translate($translator, 'agent_rules_check_current', ['count' => $count]));

        return ExitCode::Clean->value;
    }

    /**
     * The renderers for the selected targets, registered on a fresh exporter.
     *
     * Registered here rather than in the service provider because the SELECTION is this command's
     * business: a provider-wide registry would make `--target` a filter over things already built,
     * and a filter is exactly the kind of thing that stops filtering.
     *
     * @param  list<AgentContextFormat>  $targets
     */
    private function exporterFor(array $targets, Redactor $redactor): MetadataExporter
    {
        $exporter = new MetadataExporter($redactor);

        foreach ($targets as $target) {
            $exporter->register($this->rendererFor($target));
        }

        return $exporter;
    }

    private function rendererFor(AgentContextFormat $target): MetadataRenderer
    {
        return match ($target) {
            AgentContextFormat::Claude => new ClaudeMarkdownRenderer(self::GENERATOR_VERSION),
            AgentContextFormat::Cursor => new CursorRulesRenderer(self::GENERATOR_VERSION),
            AgentContextFormat::Copilot => new CopilotInstructionsRenderer(self::GENERATOR_VERSION),
        };
    }

    /**
     * The selected targets, or null when the option names something this build does not know.
     *
     * Null rather than a default. A typo answered with "all" would write three files somebody did
     * not ask for, and a typo answered with "none" would report a clean run over nothing.
     *
     * @return list<AgentContextFormat>|null
     */
    private function targets(): ?array
    {
        $target = $this->option('target');

        if (! is_string($target) || $target === '') {
            return null;
        }

        if ($target === 'all') {
            return AgentContextFormat::cases();
        }

        // `tryFrom` rather than a case-insensitive lookup: the option values are documented in the
        // signature, and a resolver that accepted `Claude` would make the accepted set unknowable —
        // the same reasoning the rule-id validator applies to suppressions.
        $format = AgentContextFormat::tryFrom($target);

        return $format instanceof AgentContextFormat ? [$format] : null;
    }

    /**
     * The `--connection` override, or null when the configured one is used.
     *
     * Present because the command's own default is `database.default`, and a project whose dev
     * default is an engine this package has no rules for would otherwise be unable to run it at
     * all — measured on a SQLite-defaulted app, where the run refused with a driver message that
     * was correct and useless.
     */
    private function connection(): ?string
    {
        $connection = $this->option('connection');

        return is_string($connection) && $connection !== '' ? $connection : null;
    }

    /** The `--output` override, or null when the target's own path is used. */
    private function overridePath(): ?string
    {
        $output = $this->option('output');

        return is_string($output) && $output !== '' ? $output : null;
    }

    /** @param  array<string, int|string>  $replace */
    private function translate(Translator $translator, string $key, array $replace = []): string
    {
        $line = $translator->get('sqlens::messages.commands.'.$key, $replace, ShippedLocale::CODE);

        return is_string($line) ? $line : $key;
    }

    /** The error stream — diagnostics go here, never onto STDOUT. */
    private function stderr(): OutputInterface
    {
        return $this->output->getErrorStyle();
    }
}
