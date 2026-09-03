<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Illuminate\Contracts\Translation\Translator;
use Illuminate\Support\Manager;
use LogicException;
use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Reporting\Agent\AgentReporter;
use Pushery\SQLens\Reporting\Agent\Redactor;
use Pushery\SQLens\Reporting\Agent\RemediationRenderer;
use Pushery\SQLens\Reporting\Console\ConsoleReporter;
use Pushery\SQLens\Reporting\Github\GithubReporter;
use Pushery\SQLens\Reporting\Json\JsonReporter;
use Pushery\SQLens\Reporting\Sarif\LocationResolver;
use Pushery\SQLens\Reporting\Sarif\SarifReporter;

/**
 * Resolves a format name to a reporter — the Laravel Manager idiom the fleet uses
 * for cache and queue drivers. `console`, `json`, `github` and `sarif` are built in; later reporters
 * register through the inherited extend() point (an extension seam, not yet public
 * API). The default format comes from `sqlens.reporting.default_format`.
 *
 * An unknown format is a hard error naming every available format — never a silent
 * fallback to console, which would hide a typo in `--format` behind a run that
 * looks like it worked.
 */
final class ReporterManager extends Manager
{
    public function getDefaultDriver(): string
    {
        $configured = $this->config->get('sqlens.reporting.default_format', 'console');

        return is_string($configured) ? $configured : 'console';
    }

    /**
     * Every format the manager can resolve — the built-in pair plus any registered
     * through extend().
     *
     * @return list<string>
     */
    public function availableFormats(): array
    {
        return array_values(array_unique(['console', 'json', 'github', 'sarif', 'agent', ...array_keys($this->customCreators)]));
    }

    /** Resolve a reporter by format, or fail loudly if the format is unknown. */
    public function reporter(?string $format = null): Reporter
    {
        $format ??= $this->getDefaultDriver();

        if (! in_array($format, $this->availableFormats(), true)) {
            throw UnknownReporterFormat::format($format, $this->availableFormats());
        }

        $reporter = $this->driver($format);

        // Guards a misuse of extend(): a registered creator that does not return a
        // Reporter is a programming error, and it fails loud rather than blowing up
        // deeper in the run with a confusing type error.
        if (! $reporter instanceof Reporter) {
            throw new LogicException(sprintf('The reporter registered for format "%s" does not implement the Reporter contract.', $format));
        }

        return $reporter;
    }

    protected function createConsoleDriver(): Reporter
    {
        // The balance is prose a person reads, so the console reporter is the one
        // place in the reporting layer that needs the translator.
        // The maintenance-window switch reaches the reporter here rather than being read inside
        // it: a reporter that fetched its own config would be a second place the run's settings
        // are resolved, and the two would eventually disagree about a run.
        $enabled = $this->container->make('config')->get('sqlens.reporting.maintenance_window', true);

        return new ConsoleReporter($this->container->make(Translator::class), $enabled !== false);
    }

    protected function createJsonDriver(): Reporter
    {
        return new JsonReporter;
    }

    protected function createGithubDriver(): Reporter
    {
        return new GithubReporter;
    }

    protected function createAgentDriver(): Reporter
    {
        // The redactor is built HERE, like the SARIF anchor below and for the same reason: a
        // reporter that fetched its own configuration would be a second place a run's settings are
        // resolved, and the two would eventually disagree about a run.
        //
        // It is a required argument rather than an optional one. A redactor a caller may omit is
        // one a caller will omit, and this is the surface where omitting it publishes somebody's
        // password with a heading on it.
        // The translator comes from the container HERE rather than inside the renderer, for the
        // reason every other resolution in this manager does: shipped code that reached for the
        // Foundation would behave differently depending on what booted it.
        return new AgentReporter(
            new Redactor(new CredentialRedaction($this->container->make('config'))),
            new RemediationRenderer($this->container->make(Translator::class)),
        );
    }

    protected function createSarifDriver(): Reporter
    {
        // Read here rather than inside the reporter, for the same reason the console reporter's
        // maintenance-window switch is: a reporter that fetched its own config would be a second
        // place the run's settings are resolved, and the two would eventually disagree about a run.
        $anchor = $this->container->make('config')->get('sqlens.reporting.sarif.anchor_file');

        return new SarifReporter(new LocationResolver(
            is_string($anchor) && trim($anchor) !== '' ? $anchor : LocationResolver::DEFAULT_ANCHOR,
        ));
    }
}
