<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Contracts\CarriesNoSeverity;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What a run says about an amplifier that was registered and did not answer.
 *
 * ## Why it is shared rather than owned by one runner
 *
 * It lived inside the lint runner, private, because for a long time exactly one route could use a
 * tool. That stopped being true when a tool arrived that reads a live CATALOG rather than a file:
 * the audit route needs the identical sentence, and the second copy of a paragraph this careful is
 * the copy that drifts.
 *
 * Nothing in here names a tool. Everything it says is asked of the diagnostic, which is what lets
 * one text serve every amplifier the package ever grows — and what keeps a run from crediting the
 * wrong one, the way {@see UnverifiableToolPrefixes} exists to prevent on the suppression side.
 */
final readonly class MissingToolNotice
{
    use CarriesNoSeverity;

    /**
     * @param  RunNotice  $notice  the identity of the ROUTE reporting this — the sentence below is
     *                             shared, the id is not. A finding out of an audit run carrying the
     *                             lint route's id would be a false statement of origin, and the
     *                             baseline fingerprints that id.
     */
    public static function for(RunNotice $notice, ToolDiagnostic $diagnostic, string $connectionName, string $projectRoot, SubjectContext $subjectContext): Finding
    {
        $tool = $diagnostic->tool;

        // Every absence gets its own sentence, because every absence has a different fix. A
        // tool that is not installed, a pinned path that does not run, a binary that will not
        // say what it is, and a version nobody measured are four different actions for the
        // reader — collapsing them into "not found" would be accurate for one of them and
        // misleading for three.
        //
        // ## Why these sentences are English in code and not in `lang/`
        //
        // They WERE translation keys, and that was the wrong classification. A finding is the
        // MACHINE surface — JSON, SARIF, the baseline fingerprint, what an agent parses — and a
        // translated finding makes that surface depend on `app.locale`: the same tree reported
        // in German on a laptop and in English in CI, with the baseline unable to recognize its
        // own entries across the two. `LintDeterminismTest` states the contract in its own name
        // ("the machine surface is locale-free") and it caught exactly this.
        //
        // So they follow the convention every one of the ~105 rule messages already follows:
        // built here, in English, from the rule's own knowledge. `lang/` keeps what it is for —
        // the console and CLI chrome on stderr, which is the human surface and may be localized.
        //
        // What the binary printed is quoted rather than parsed, so the reader compares it against
        // the window themselves. The configured path is deliberately absent from all five: a
        // finding has to be safe to paste into a public issue, and an absolute path carries a
        // username often enough to be a bad habit.
        $message = match ($diagnostic->resolution) {
            ToolResolution::UnsupportedPlatform => sprintf(
                '%s has no build for this platform, so it could not run. It would have added: %s. The platform-neutral core rules still ran.',
                $tool->name(),
                $tool->whatItEnables(),
            ),
            ToolResolution::ConfiguredPathNotExecutable => sprintf(
                '%s is pinned to a path in sqlens.tools, and nothing runnable answers there, so the rules it powers did not run. It would have added: %s. SQLens does not quietly fall back to PATH — a pinned path says which binary you want. Correct the path, or remove it to search PATH.',
                $tool->name(),
                $tool->whatItEnables(),
            ),
            ToolResolution::VersionUnreadable => sprintf(
                '%s was found, but it did not report a version SQLens could read, so the rules it powers did not run. It would have added: %s. The version is never guessed: what SQLens reads out of a tool depends on which one answered.',
                $tool->name(),
                $tool->whatItEnables(),
            ),
            ToolResolution::VersionUnsupported => sprintf(
                '%s reports "%s", and SQLens has measured its output only for %s, so the rules it powers did not run. It would have added: %s. Install a version in that range, or pin one in sqlens.tools.',
                $tool->name(),
                $diagnostic->version ?? '',
                $tool->versionWindow()->describe(),
                $tool->whatItEnables(),
            ),
            default => sprintf(
                '%s was not found on the configured path or PATH, so the rules it powers did not run. It would have added: %s. Install it, or set the tool path in sqlens.tools.',
                $tool->name(),
                $tool->whatItEnables(),
            ),
        };

        return Finding::undetermined(
            $notice->id(),
            $notice->messagePrefix(),
            $message,
            UndeterminedReason::MissingExternalTool,
            Location::inCallsite('tool:'.$tool->name(), 0, 'connection '.$connectionName, $projectRoot),
            $notice->category(),
            $notice->level(),
            $notice->stability(),
            $notice->documentationUrl(),
            $subjectContext,
        );
    }
}
