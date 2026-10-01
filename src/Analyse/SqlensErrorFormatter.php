<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use JsonException;
use PHPStan\Analyser\InternalError;
use PHPStan\Command\AnalysisResult;
use PHPStan\Command\ErrorFormatter\ErrorFormatter;
use PHPStan\Command\Output;
use stdClass;

/**
 * `--error-format=sqlens`: PHPStan's JSON result, with the trace of the extension that wrote it.
 *
 * The document has the shape `--error-format=json` writes, `totals`, `files` and `errors`, so
 * anything that reads one reads the other. Two things differ. Each message carries its message,
 * line, whether it can be ignored and its identifier, but not PHPStan's tip, which is formatted
 * for a terminal. And under {@see AnalyseResultTrace::KEY} it carries what {@see AnalyseResultTrace}
 * describes: the format's version, and the message of every internal error PHPStan hit while it
 * analyzed.
 *
 * The exit code is PHPStan's own, so a pipeline step that fails on errors keeps failing on them.
 */
final readonly class SqlensErrorFormatter implements ErrorFormatter
{
    /**
     * @throws JsonException when a message cannot be encoded, which PHPStan reports instead of
     *                       writing half a document
     */
    public function formatErrors(AnalysisResult $analysisResult, Output $output): int
    {
        $files = [];

        foreach ($analysisResult->getFileSpecificErrors() as $error) {
            $message = [
                'message' => $error->getMessage(),
                'line' => $error->getLine(),
                'ignorable' => $error->canBeIgnored(),
            ];

            if ($error->getIdentifier() !== null) {
                $message['identifier'] = $error->getIdentifier();
            }

            $file = $error->getFile();
            $files[$file] ??= ['errors' => 0, 'messages' => []];
            $files[$file]['errors']++;
            $files[$file]['messages'][] = $message;
        }

        $output->writeRaw(json_encode([
            'totals' => [
                'errors' => count($analysisResult->getNotFileSpecificErrors()),
                'file_errors' => count($analysisResult->getFileSpecificErrors()),
            ],
            // An object even when empty, as PHPStan writes it: `files` is keyed by path.
            'files' => $files === [] ? new stdClass : $files,
            'errors' => $analysisResult->getNotFileSpecificErrors(),
            AnalyseResultTrace::KEY => [
                'version' => AnalyseResultTrace::VERSION,
                'internal_errors' => array_map(
                    static fn (InternalError $error): string => $error->getMessage(),
                    $analysisResult->getInternalErrorObjects(),
                ),
            ],
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return $analysisResult->hasErrors() ? 1 : 0;
    }
}
