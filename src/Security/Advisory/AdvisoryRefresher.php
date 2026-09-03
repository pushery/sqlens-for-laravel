<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\Client\Factory;
use Pushery\SQLens\PackageVersion;
use Throwable;

/**
 * The one place this package reaches the network, and only when a person asks it to.
 *
 * ## Why the source has no default
 *
 * Shipping an endpoint would be this package endorsing somebody else's terms of use on behalf of
 * every consumer — their rate limits, their attribution, their license, none of which this package
 * can accept for anyone. So `sqlens.security.advisories.source` is null out of the box and the
 * refresh says exactly that when it is asked to run without one.
 *
 * The source must serve a document in THIS package's advisory format. That is not a limitation
 * dressed as a decision: it means the package never parses a third party's shape, so it never
 * inherits a change to that shape, and an organization can generate the file from whatever source
 * their own terms allow.
 *
 * ## Why it validates by reading, not by checking
 *
 * The fetched bytes are written to a temporary file and read back through {@see EolRepository} —
 * the same parser the rules judge from. A second validator would eventually disagree with the
 * reader about what a valid file is, and the disagreement would surface as a refresh that succeeds
 * and a run that then reports the data as unreadable.
 *
 * ## Why it never writes to the package
 *
 * The target is the path {@see EolRepository} resolves, and `vendor/` is not among the candidates.
 * A refresh that wrote into the installed package would be undone by the next `composer install`,
 * silently, leaving an operator certain they had refreshed data that is once again old.
 */
final readonly class AdvisoryRefresher
{
    /** Seconds. Hard, because a refresh that hangs is worse than one that fails: nobody waits twice. */
    private const int TIMEOUT_SECONDS = 15;

    /** One retry, not three. A source that is down stays down for longer than a command should stand there. */
    private const int RETRIES = 2;

    public function __construct(
        private Config $config,
        private EolRepository $advisories,
        private string $basePath,
        private Factory $http,
    ) {}

    public function refresh(): AdvisoryRefreshOutcome
    {
        $source = $this->config->get('sqlens.security.advisories.source');

        if (! is_string($source) || trim($source) === '') {
            return AdvisoryRefreshOutcome::refused(
                'no advisory source is configured, and this package ships no default. Set '
                .'`sqlens.security.advisories.source` to a URL serving a document in this package\'s '
                .'advisory format. There is no default because shipping one would accept somebody '
                .'else\'s terms of use on your behalf — the license, the rate limit and the '
                .'attribution are yours to agree to.',
            );
        }

        $target = $this->target();

        if ($target === null) {
            return AdvisoryRefreshOutcome::refused(
                'the advisory file would have to be written inside the installed package, and this '
                .'refresh never does that: the next `composer install` would undo it silently, and '
                .'you would be certain you had refreshed data that is old again. Set '
                .'`sqlens.security.advisories.path`, or publish the file into your own '
                .'`resources/data/eol.json`, and the refresh writes there.',
            );
        }

        $body = $this->fetch($source);

        // A refusal comes back as the outcome itself rather than as a flag beside a null, because
        // this class is readonly and a failure sentence stashed in a property would be state it
        // cannot hold — and threading it as a second return value is how a caller ends up checking
        // the wrong one of the two.
        if ($body instanceof AdvisoryRefreshOutcome) {
            return $body;
        }

        return $this->replace($target, $body);
    }

    /** The bytes the source served, or the refusal that explains why there are none. */
    private function fetch(string $source): AdvisoryRefreshOutcome|string
    {
        try {
            $response = $this->http
                ->timeout(self::TIMEOUT_SECONDS)
                // `throw: false`, and it is load-bearing rather than a preference. With the
                // default, a retried request that ends on an error STATUS raises a RequestException
                // instead of returning the response — so the branch below could never run, and the
                // operator got an exception's text where a written sentence belongs. Measured: the
                // coverage gate named those lines as unreachable, which is how it surfaced.
                ->retry(self::RETRIES, 250, throw: false)
                // Named rather than anonymous: an operator reading their own access log should be
                // able to tell which tool asked, and a version makes a report about a bad response
                // actionable.
                ->withHeaders(['User-Agent' => 'pushery/sqlens-for-laravel '.PackageVersion::forUserAgent()])
                ->get($source);
        } catch (Throwable $exception) {
            return AdvisoryRefreshOutcome::refused(sprintf(
                'the advisory source "%s" could not be reached, so the existing file is unchanged: %s',
                $source,
                $exception->getMessage(),
            ));
        }

        if ($response->failed()) {
            return AdvisoryRefreshOutcome::refused(sprintf(
                'the advisory source "%s" answered %d, so the existing file is unchanged',
                $source,
                $response->status(),
            ));
        }

        return $response->body();
    }

    /**
     * Read the fetched bytes with the REAL parser, diff them, and write only if they are valid.
     *
     * No temporary file. The parser takes the bytes directly, so the response never exists anywhere
     * but in memory — an unvalidated copy of somebody else's answer sitting in a temp directory is a
     * second thing to reason about for no benefit, and the security preset refuses `tempnam` for
     * exactly that class of reason.
     */
    private function replace(string $target, string $body): AdvisoryRefreshOutcome
    {
        $fetched = EolRepository::forDocument($body, 'the advisory source');

        if (! $fetched->data instanceof EolData) {
            return AdvisoryRefreshOutcome::refused(sprintf(
                'the advisory source answered with data this package cannot read, so the existing '
                .'file was left exactly as it was: %s',
                (string) $fetched->reason,
            ));
        }

        $changes = $this->diff($this->advisories->lookup()->data, $fetched->data);

        if ($changes === [] && is_file($target)) {
            return AdvisoryRefreshOutcome::unchanged($target);
        }

        return $this->write($target, $fetched->data, $changes);
    }

    /** @param  list<string>  $changes */
    private function write(string $target, EolData $data, array $changes): AdvisoryRefreshOutcome
    {
        $directory = dirname($target);

        if (! is_dir($directory) && ! @mkdir($directory, 0o755, true) && ! is_dir($directory)) {
            return AdvisoryRefreshOutcome::refused(sprintf('the directory "%s" could not be created, so nothing was written', $directory));
        }

        // Re-serialized from the PARSED data rather than the raw body, and sorted. Writing the bytes
        // as they arrived would let the source decide the file's key order, which turns every
        // refresh into a diff nobody can review — the whole point of committing this file.
        $encoded = json_encode($this->serialize($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        if (@file_put_contents($target, $encoded."\n") === false) {
            return AdvisoryRefreshOutcome::refused(sprintf('"%s" could not be written, so the existing file is unchanged', $target));
        }

        return AdvisoryRefreshOutcome::written($target, $changes);
    }

    /**
     * What moved between the file on disk and the one that arrived.
     *
     * A line per cycle rather than a byte diff: somebody about to commit this wants to know that
     * PostgreSQL 14's end date moved, not that line 87 changed. An empty list means the fetch agreed
     * with what is already there.
     *
     * @return list<string>
     */
    private function diff(?EolData $before, EolData $after): array
    {
        $changes = [];
        $old = $before instanceof EolData ? $this->flatten($before) : [];
        $new = $this->flatten($after);

        foreach ($new as $key => $entry) {
            if (! isset($old[$key])) {
                $changes[] = sprintf('+ %s — new, supported until %s', $key, $entry['eol']);

                continue;
            }

            foreach (['eol' => 'end of life', 'latest' => 'latest patch', 'release' => 'release date'] as $field => $label) {
                if ($old[$key][$field] !== $entry[$field]) {
                    $changes[] = sprintf('~ %s — %s %s → %s', $key, $label, $old[$key][$field] ?? 'none', $entry[$field] ?? 'none');
                }
            }
        }

        foreach (array_keys($old) as $key) {
            if (! isset($new[$key])) {
                $changes[] = sprintf('- %s — no longer in the data', $key);
            }
        }

        sort($changes);

        return $changes;
    }

    /** @return array<string, array{eol: string, latest: ?string, release: string}> */
    private function flatten(EolData $data): array
    {
        $flat = [];

        foreach ($data->cycles as $product => $cycles) {
            foreach ($cycles as $cycle) {
                $flat["{$product} {$cycle->cycle}"] = [
                    'eol' => $cycle->eolDate,
                    'latest' => $cycle->latestPatch,
                    'release' => $cycle->releaseDate,
                ];
            }
        }

        ksort($flat);

        return $flat;
    }

    /** @return array<string, mixed> */
    private function serialize(EolData $data): array
    {
        $products = [];

        foreach ($data->products() as $product) {
            $cycles = $data->cycles[$product];
            usort($cycles, static fn (EolCycle $a, EolCycle $b): int => $a->cycle <=> $b->cycle);

            $products[$product] = ['cycles' => array_map(static fn (EolCycle $c): array => [
                'cycle' => $c->cycle,
                'latest_patch' => $c->latestPatch,
                'release_date' => $c->releaseDate,
                'eol_date' => $c->eolDate,
                'lts' => $c->lts,
                'note' => $c->note,
            ], $cycles)];
        }

        return [
            'schema_version' => EolRepository::SCHEMA_VERSION,
            'compiled_on' => $data->compiledOn,
            'products' => $products,
        ];
    }

    /** Where the refresh may write: the configured path, else the application's own published copy. */
    private function target(): ?string
    {
        $configured = $this->config->get('sqlens.security.advisories.path');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        // The bundled copy is deliberately not a candidate — see the class note. An application with
        // no base path of its own has nowhere this refresh is allowed to write.
        return $this->basePath === '' ? null : $this->basePath.'/'.EolRepository::BUNDLED_FILE;
    }
}
