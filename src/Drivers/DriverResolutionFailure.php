<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * A named driver-resolution failure — the "no silent green" of driver selection.
 * It carries the reason and a short English detail; the generic constructor is
 * private so a failure can only be built through a named factory that supplies
 * the reason.
 *
 * It is a VALUE, not an exception. An unsupported engine is a finding about the
 * project, not a crash of the tool, and a stack trace in a report tells a user
 * nothing they can act on.
 *
 * The reason values are stable ENGLISH identifiers and stay that way. They reach
 * the JSON envelope, so a translated reason id would be a breaking change per
 * language. The TEXT is translated; the IDENTITY is not.
 */
final readonly class DriverResolutionFailure
{
    /**
     * @param  array<string, string>  $placeholders  the values this reason's message text
     *                                               needs, supplied BY the factory that knows them. Never a host, a user or a
     *                                               password: a finding has to be safe to paste into a public issue.
     */
    private function __construct(
        public DriverResolutionReason $reason,
        public string $detail,
        public array $placeholders = [],
    ) {}

    public static function reservedDriver(string $driver): self
    {
        return new self(
            DriverResolutionReason::ReservedDriver,
            sprintf('driver "%s" is a reserved non-goal engine and is not supported', $driver),
        );
    }

    public static function unknownDriver(string $driver): self
    {
        return new self(
            DriverResolutionReason::UnknownDriver,
            sprintf('driver "%s" is neither built-in nor registered', $driver),
        );
    }

    public static function missingDriverKey(string $connectionName): self
    {
        return new self(
            DriverResolutionReason::MissingDriverKey,
            sprintf('connection "%s" declares no driver key', $connectionName),
        );
    }

    /**
     * @param  list<string>  $configured  the connection names the host application defines
     */
    public static function connectionNotFound(string $connectionName, array $configured = []): self
    {
        // An empty name is not a typo, it is an unset config: `sqlens.connection`
        // and `database.default` are both blank. Reporting `under the name ""`
        // would be true and useless.
        if ($connectionName === '') {
            return new self(
                DriverResolutionReason::ConnectionNotFound,
                'no connection was named: neither sqlens.connection nor database.default is set',
                ['configured' => self::nameList($configured)],
            );
        }

        // Naming what IS configured turns a dead end into a fixable message. Only
        // the NAMES — never a host, a user or a password.
        return new self(
            DriverResolutionReason::ConnectionNotFound,
            $configured === []
                ? sprintf('no connection is configured under the name "%s", and the application configures none at all', $connectionName)
                : sprintf('no connection is configured under the name "%s"; configured names are: %s', $connectionName, implode(', ', $configured)),
            ['configured' => self::nameList($configured)],
        );
    }

    /** @param  list<string>  $configured */
    private static function nameList(array $configured): string
    {
        return $configured === [] ? 'nothing' : implode(', ', $configured);
    }

    public static function versionBelowFloor(string $driver, string $detected, string $required): self
    {
        return new self(
            DriverResolutionReason::VersionBelowFloor,
            sprintf('%s reports version %s, below the supported floor of %s', $driver, $detected, $required),
            ['detected' => $detected, 'required' => $required],
        );
    }

    public static function unknownServerVersion(string $driver, string $detail): self
    {
        return new self(
            DriverResolutionReason::UnknownServerVersion,
            sprintf('the version of the %s server could not be established: %s', $driver, $detail),
        );
    }

    public static function mariaDbBehindMysqlDriver(string $banner): self
    {
        return new self(
            DriverResolutionReason::MariaDbBehindMysqlDriver,
            sprintf('the connection uses the mysql driver, but the server reports "%s" — a MariaDB', $banner),
            ['detected' => $banner],
        );
    }

    public static function unverifiedEngineIdentity(string $driver): self
    {
        return new self(
            DriverResolutionReason::UnverifiedEngineIdentity,
            sprintf('no open connection confirmed that the %s driver really addresses that engine', $driver),
        );
    }

    /**
     * The three-valued outcome this failure maps to. Never a pass: a driver SQLens
     * cannot reason about means the checks did not run, not that they passed.
     */
    public function undeterminedReason(): UndeterminedReason
    {
        return match ($this->reason) {
            DriverResolutionReason::ReservedDriver, DriverResolutionReason::UnknownDriver => UndeterminedReason::UnsupportedEngine,
            // A connection the app never declared, or one without a driver key, is a
            // configuration finding rather than an engine finding — the distinction
            // survives all the way into the report.
            DriverResolutionReason::MissingDriverKey => UndeterminedReason::StructurallyNotApplicable,
            // Its own reason: a name the host application never defined is a
            // different problem from a connection that exists but says nothing
            // about its engine, and the two need different fixes.
            DriverResolutionReason::ConnectionNotFound => UndeterminedReason::ConnectionNotConfigured,
            // The ENGINE is supported here; the version is not. It is still an
            // unsupported combination, so the rules did not run — but the message
            // above says "upgrade", not "wrong engine", because those are different
            // actions for the reader.
            DriverResolutionReason::VersionBelowFloor => UndeterminedReason::ServerBelowSupportedFloor,
            DriverResolutionReason::UnknownServerVersion => UndeterminedReason::UnknownServerVersion,
            DriverResolutionReason::MariaDbBehindMysqlDriver => UndeterminedReason::UnsupportedEngine,
            // Not knowing WHICH engine answers is its own gap, distinct from knowing
            // the engine and not its version.
            DriverResolutionReason::UnverifiedEngineIdentity => UndeterminedReason::UnknownServerVersion,
        };
    }

    /** The stable page explaining this exact case, per reason. */
    public function documentationUrl(): string
    {
        return DocumentationSite::page('drivers/unsupported').'#'.str_replace('_', '-', $this->reason->value);
    }

    /** The translation key of the human-facing text — the identity above stays English. */
    public function translationKey(): string
    {
        return 'sqlens::messages.drivers.'.$this->reason->value;
    }
}
