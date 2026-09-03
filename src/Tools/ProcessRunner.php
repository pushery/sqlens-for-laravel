<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * The seam between the tool locator and the system: finding a binary and asking it
 * for its version. Kept behind a contract so the locator's logic is tested against a
 * fake — a real subprocess in a unit test is slow and machine-dependent — and so the
 * "no implicit network" promise is provable: an implementation only ever runs a LOCAL
 * binary, it never reaches out.
 */
interface ProcessRunner
{
    /** The absolute path to a binary on the system search path, or null if it is not there. */
    public function locate(string $binaryName): ?string;

    /**
     * The first line a binary reports for `<path> --version`, trimmed, or null when it
     * could not be run. Bounded in time — a version probe never hangs a run.
     */
    public function version(string $binaryPath): ?string;

    /**
     * Run a located binary with the given arguments and report what happened.
     *
     * The arguments are a LIST, never a command string. That is not a style preference: a
     * string has to be parsed by something, and whatever parses it also interprets quoting,
     * globbing and separators. A list is handed to the kernel as it stands, so a path with a
     * space in it is a path with a space in it and nothing can turn an argument into a second
     * command.
     *
     * Nothing here throws. A tool is an optional amplifier — a binary that hangs, is not
     * executable, or is not a program at all must end as a named result, never as an exception
     * that takes the surrounding run with it.
     *
     * @param  list<string>  $arguments  argv after the binary itself
     * @param  float  $timeoutSeconds  the bound this single invocation gets
     * @param  string|null  $stdin  what to feed the child on standard input, or null for none.
     *                              Its own channel rather than a temp file because a file is a
     *                              side effect: it needs a location, a cleanup path that also
     *                              runs when the run fails, and it puts a machine-specific
     *                              absolute path into whatever the tool reports back.
     * @param  array<string, string>  $environment  variables the CALLER states for this one child.
     *                                              An implementation never INHERITS the ambient
     *                                              environment — that is how a linter ends up
     *                                              talking to whatever database the operator's
     *                                              shell happened to export, and how a result
     *                                              comes to depend on whose terminal ran it. What
     *                                              is named here comes from the configuration
     *                                              under audit instead, which is the thing being
     *                                              measured. Secrets belong HERE and never in
     *                                              `$arguments`, where they are readable in `ps`.
     */
    public function run(string $binaryPath, array $arguments, float $timeoutSeconds, ?string $stdin = null, array $environment = []): ToolRunResult;
}
