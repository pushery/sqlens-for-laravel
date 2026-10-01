<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Closure;
use Composer\InstalledVersions;
use Throwable;

/**
 * Whether the installed `laravel/mcp` is a release this server is written against.
 *
 * {@see ServesMcp::isAvailable()} answers whether the SDK is there at all, and that is not enough.
 * Before 0.8 the SDK kept its transport and exception classes in other namespaces, and the handshake
 * method this server registers overrides the SDK's own with a signature that names the current ones.
 * Under an older SDK, which `laravel/boost` up to 2.4 still installs, PHP cannot check that signature
 * when the client's first `initialize` loads the class, and the process ends in a fatal that the
 * client sees only as a disconnect. Asked before the server starts, the same fact becomes a sentence
 * the operator can act on.
 *
 * Read from Composer rather than by probing for one of the classes that moved: the SDK loads those
 * lazily, and asking whether one exists would load it.
 */
final readonly class McpSdkVersion
{
    public const string PACKAGE = 'laravel/mcp';

    /** The major release the handshake is written and measured against. */
    public const int SPOKEN_MAJOR = 1;

    /** @param  Closure(): ?string  $installed  the installed version as Composer reports it, or null */
    public function __construct(private Closure $installed) {}

    /**
     * The package name is a parameter so a test can reach the branch for a package that is not
     * installed; inside this suite the SDK always is.
     */
    public static function fromComposer(string $package = self::PACKAGE): self
    {
        return new self(static function () use ($package): ?string {
            try {
                return InstalledVersions::getPrettyVersion($package);
            } catch (Throwable) {
                // Not installed as a Composer package. Whether it is there at all is the other question.
                return null;
            }
        });
    }

    /**
     * The installed version when it is a release this server is not written against, or null.
     *
     * Null too when Composer reports no version, or one that names no release, such as a branch
     * alias: the check exists for the releases known to break, and refusing a version it cannot read
     * would stop a developer running the SDK from source for no measured reason.
     */
    public function unsupported(): ?string
    {
        $version = ($this->installed)();

        if ($version === null || preg_match('/^v?(\d+)\./', $version, $major) !== 1) {
            return null;
        }

        return (int) $major[1] === self::SPOKEN_MAJOR ? null : $version;
    }
}
