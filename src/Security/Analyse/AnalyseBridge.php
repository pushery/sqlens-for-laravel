<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Analyse;

use JsonException;
use Pushery\SQLens\Analyse\AnalyseRuleCatalog;
use Pushery\SQLens\Analyse\AnalyseRuleMetadata;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The injection findings, read out of a result PHPStan already wrote.
 *
 * ## Why this reads a file instead of running an analyzer
 *
 * The injection rules are a PHPStan extension, and PHPStan is the project's tool rather than this
 * package's. A security command that started orchestrating somebody else's analyzer would be
 * deciding for them which configuration, which level and which baseline applied — and would be wrong
 * about all three on the first project that had opinions.
 *
 * So the contract is the file: PHPStan runs as its own step, writes `--error-format=json`, and this
 * reads it. In CI that is one extra line in a workflow both steps already share a workspace with.
 *
 * ## Every way this can fail to answer is NAMED
 *
 * Not configured, a path that is not there, a file that is not JSON, a document whose shape is not
 * PHPStan's — each is an `undetermined` carrying which one it was. None of them is silence, because a
 * codebase nobody analyzed and a codebase with no raw SQL produce the same empty list, and only one
 * of them is good news.
 *
 * ## The identifier is the join, and it is PHPStan's to own
 *
 * Each analyse rule declares two names: its own `SEC.INJ.*` id and the `identifier` PHPStan reports
 * it under. The second is what a JSON document carries, so it is what this matches on — read from
 * {@see AnalyseRuleCatalog} rather than typed here, because a hand-kept copy of that pairing would
 * drift the first time a rule was renamed and would drift silently.
 *
 * A diagnostic whose identifier belongs to no analyse rule is DROPPED rather than reported: a project
 * runs PHPStan for its own reasons, and its own errors are not this suite's findings to relay.
 */
final readonly class AnalyseBridge
{
    public function __construct(
        private AnalyseMode $mode,
        private ?string $resultPath,
        private string $projectRoot,
    ) {}

    /**
     * What the analyse half contributes, or the clause saying why it contributed nothing.
     */
    public function read(SubjectContext $context): AnalyseReading
    {
        if ($this->mode === AnalyseMode::Off) {
            return AnalyseReading::didNotRun(
                'the analyse half is switched off (`sqlens.security.analyse.mode` is `off`), so no '
                .'raw-SQL call site was examined — which says nothing about SQL injection rather '
                .'than saying there is none',
            );
        }

        $path = $this->resultPath;

        if ($path === null || trim($path) === '') {
            return AnalyseReading::didNotRun(
                'the analyse half is set to `read` and `sqlens.security.analyse.result_path` names '
                .'no file, so there was nothing to read',
            );
        }

        $absolute = $this->absolute($path);

        if (! is_file($absolute)) {
            return AnalyseReading::didNotRun(sprintf(
                'no PHPStan result at `%s` — the analyse step either has not run yet or wrote elsewhere',
                $path,
            ));
        }

        $raw = @file_get_contents($absolute);

        if ($raw === false) {
            return AnalyseReading::didNotRun(sprintf('the PHPStan result at `%s` could not be read', $path));
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            return AnalyseReading::didNotRun(sprintf(
                'the PHPStan result at `%s` is not valid JSON (%s)',
                $path,
                $failure->getMessage(),
            ));
        }

        if (! is_array($decoded) || ! isset($decoded['files']) || ! is_array($decoded['files'])) {
            return AnalyseReading::didNotRun(sprintf(
                'the document at `%s` carries no `files` map, so it is not a PHPStan JSON result — '
                .'reading it anyway would report findings this package cannot vouch for',
                $path,
            ));
        }

        return AnalyseReading::of($this->mapped($decoded['files'], $context));
    }

    /**
     * @param  array<mixed>  $files
     * @return list<Finding>
     */
    private function mapped(array $files, SubjectContext $context): array
    {
        $byIdentifier = $this->rulesByIdentifier();
        $findings = [];

        foreach ($files as $file => $entry) {
            if (! is_string($file) || ! is_array($entry) || ! isset($entry['messages']) || ! is_array($entry['messages'])) {
                continue;
            }

            foreach ($entry['messages'] as $message) {
                if (! is_array($message)) {
                    continue;
                }

                $identifier = $message['identifier'] ?? null;
                $rule = is_string($identifier) ? ($byIdentifier[$identifier] ?? null) : null;

                // Somebody else's diagnostic. A project runs PHPStan for its own reasons, and
                // relaying its unrelated errors as security findings would put this package's name
                // on somebody else's opinion.
                if (! $rule instanceof AnalyseRuleMetadata) {
                    continue;
                }

                $findings[] = Finding::fail(
                    $rule->id,
                    $rule->messagePrefix,
                    is_string($message['message'] ?? null) ? $message['message'] : '(the analyzer reported no message)',
                    Location::inCallsite(
                        $file,
                        is_int($message['line'] ?? null) ? $message['line'] : 0,
                        $identifier,
                        $this->projectRoot,
                    ),
                    $rule->category,
                    $rule->level,
                    $rule->stability,
                    $rule->documentationUrl(),
                    $context,
                    $rule->severity,
                );
            }
        }

        return $findings;
    }

    /** @return array<string, AnalyseRuleMetadata> */
    private function rulesByIdentifier(): array
    {
        $byIdentifier = [];

        foreach (AnalyseRuleCatalog::metadata() as $rule) {
            if ($rule->reportedIdentifier !== null) {
                $byIdentifier[$rule->reportedIdentifier] = $rule;
            }
        }

        return $byIdentifier;
    }

    private function absolute(string $path): string
    {
        // Repository-relative, like every other path this package accepts. An absolute one still
        // works, because a CI step that knows its own workspace should not be forced to compute a
        // relative path back to it.
        //
        // A STREAM URL is left alone as well, and that is a fix rather than a courtesy: `s3://…`
        // glued behind a project root becomes a path that cannot exist, so a project pointing this
        // at a registered wrapper would be told "no PHPStan result at …" — a wrong reason, which is
        // worse here than no reason at all. A scheme is already absolute by definition.
        if (str_contains($path, '://')) {
            return $path;
        }

        return str_starts_with($path, DIRECTORY_SEPARATOR)
            ? $path
            : $this->projectRoot.DIRECTORY_SEPARATOR.ltrim($path, DIRECTORY_SEPARATOR);
    }
}
