<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Sarif;

use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The fourth reporter: SARIF 2.1.0, the format a foreign pipeline reads.
 *
 * Uploaded to GitHub, the findings land in the code-scanning tab with a history of their own —
 * assigned, dismissed, reopened — instead of scrolling past in a job log nobody reopens. That is the
 * whole point of the format, and it is why {@see SarifDocument} is careful about the fingerprint
 * rather than merely about the schema: a document that validates but is not STABLE opens a fresh
 * alert for the same problem every night, and a tab full of duplicates is a tab people mute.
 *
 * Like the JSON reporter, this writes one document verbatim to the given output, so a run
 * redirecting `--format=sarif` to a file must keep diagnostics off this stream for the file to stay
 * valid SARIF. Everything about WHAT is emitted lives on the document; this class is the write path
 * and the format name, deliberately nothing more — a reporter that decided anything would be a
 * second place the run's meaning is made.
 */
final readonly class SarifReporter implements Reporter
{
    /**
     * The location resolver, injected rather than built here.
     *
     * It carries the project's configured anchor file, and a reporter that read that itself would be
     * a second place the run's settings are resolved. Defaulted so a hand-constructed reporter — a
     * test, an extension seam — still works without knowing about the config surface.
     */
    public function __construct(private LocationResolver $locations = new LocationResolver) {}

    public function name(): string
    {
        return 'sarif';
    }

    public function report(Result $result, RunContext $context, OutputInterface $out): void
    {
        // The same flags the JSON reporter uses, and for the same measured reason: captured SQL can
        // carry invalid UTF-8 — a latin1 column value, a truncated multibyte sequence — and that
        // must not abort the whole report. The bad bytes become U+FFFD and serialization continues,
        // while JSON_THROW_ON_ERROR still catches a genuine structural bug.
        $out->writeln(json_encode(
            SarifDocument::for($result, $context, $this->locations)->toArray(),
            JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));
    }
}
