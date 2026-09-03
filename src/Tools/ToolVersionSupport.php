<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Whether a tool's reported version is one SQLens has actually verified its output against.
 *
 * Three states rather than a boolean, because the two ways of failing need different
 * words in front of a user. A version that could not be READ means we do not know what
 * answered; a version that is out of WINDOW means we know exactly what answered and have
 * never checked its output. The first is fixed by finding out why `--version` says
 * nothing, the second by installing a different build — and a single "unsupported" would
 * send half the readers down the wrong path.
 *
 * Neither is a pass. A tool whose version is unknown is a tool whose output format is
 * unknown, and parsing an unknown format is how a finding lands on the wrong line, or
 * quietly stops landing at all.
 */
enum ToolVersionSupport
{
    /** The version was read and falls inside the window this tool declares. */
    case Supported;

    /**
     * The binary answered nothing, or answered something this tool cannot parse as its
     * version. Never resolved by guessing: an assumed version is an assumed output format.
     */
    case Unreadable;

    /** The version was read cleanly and lies outside the verified window. */
    case OutOfWindow;
}
