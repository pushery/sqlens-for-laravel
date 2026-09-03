<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Json;

use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The machine-readable reporter: it emits the versioned JsonEnvelope as one
 * deterministic document. The document goes to the given output verbatim, so a run
 * that redirects `--format=json` to a file must keep diagnostics off this stream
 * (see the console-output spike) for the file to stay valid JSON.
 */
final class JsonReporter implements Reporter
{
    public function name(): string
    {
        return 'json';
    }

    public function report(Result $result, RunContext $context, OutputInterface $out): void
    {
        // JSON_INVALID_UTF8_SUBSTITUTE: captured SQL can contain invalid UTF-8 (a
        // latin1 column value, a truncated multibyte sequence). It must NOT abort the
        // whole report — the bad bytes become U+FFFD and serialization continues.
        // JSON_THROW_ON_ERROR still catches genuine structural bugs (they cannot come
        // from bad UTF-8 once it is substituted). Unescaped slashes and unicode keep
        // paths and non-ASCII readable; no timestamp, no absolute path in the data.
        $out->writeln(json_encode(
            JsonEnvelope::for($result, $context)->toArray(),
            JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));
    }
}
