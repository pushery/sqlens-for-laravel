<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\InstanceScope;
use Pushery\SQLens\Rules\RuleDeprecation;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\VersionWindow;
use Pushery\SQLens\Severity\Severity;

/**
 * The central contract every rule in the package fulfills — and, from 1.0, the
 * extension API third-party rule packs implement. Anything missing here has to
 * be retrofitted into every single rule later, so the metadata surface is cut
 * whole, once.
 *
 * Two axes, never merged: level() models strictness appetite, severity() models
 * risk. A rule in a severity-gated category (security/privacy) may leave
 * severity() non-null while its level still places it in the catalog; the
 * engine gates the two independently.
 *
 * Version awareness is mandatory, not per-rule bolt-on: versionWindow() has no
 * default. The engine evaluates the window BEFORE appliesTo(); a real version
 * outside the window produces NO finding, an unknown version produces an
 * undetermined finding with a named reason — never a silent skip. The fallback
 * chain (real version → assume_server_version pin → unknown) is wired in a later
 * layer.
 *
 * Rule id, message prefix and documentation URL are public API from 1.0 — they
 * are required methods so no rule can exist without them.
 *
 * evaluate() is side-effect free with respect to the database: it opens no
 * connection, writes nothing, takes no lock. All data reaches a rule through the
 * subject, so a fake subject with no connection is enough to evaluate any core
 * rule (primum non nocere). An architecture test enforces the DB-agnostic core.
 */
interface Rule
{
    /**
     * The stable, unique rule id (public API from 1.0, e.g.
     * `PG.L2.INDEX_NOT_CONCURRENT`). Never recycled once retired.
     */
    public function id(): string;

    public function category(): Category;

    public function level(): Level;

    /**
     * The risk axis, orthogonal to level(). Null for rules that are gated purely
     * by level; non-null for severity-gated categories (security/privacy).
     */
    public function severity(): ?Severity;

    public function stability(): StabilityTier;

    /**
     * How firmly this rule can stand behind its verdict — deterministic or heuristic.
     *
     * It is a method on the contract rather than an opt-in marker (the shape
     * {@see StatisticsDependent} uses) because confidence is
     * a property EVERY rule has, not a rare capability a few rules add. A marker would
     * let a heuristic rule stay silent by simply not implementing it — and silence
     * would read as certainty, which is exactly the claim a heuristic must not make.
     * Stating it is the point.
     *
     * Distinct from {@see stability()}: confidence describes what a FINDING is worth,
     * stability describes how settled the RULE is. A mature rule can be heuristic, and
     * a preview rule can be deterministic.
     */
    public function confidence(): Confidence;

    /**
     * The deprecation marker, or null for a rule that is deliberately not
     * deprecated — a statement, never a default to forget.
     */
    public function deprecation(): ?RuleDeprecation;

    /**
     * The server-version window this rule applies to. Mandatory and without a
     * default: the engine evaluates it before appliesTo(), so a rule can never
     * fire outside the versions it was written for. Use VersionWindow::unbounded()
     * for a rule with no version restriction — a deliberate, explicit choice.
     */
    public function versionWindow(): VersionWindow;

    /**
     * The downtime class this rule attaches to its findings, or null for a rule
     * whose findings carry none (a convention rule). Metadata a deploy script
     * reads without parsing prose.
     */
    public function downtimeClass(): ?DowntimeClass;

    /**
     * The i18n message prefix for this rule's findings (public API from 1.0).
     */
    public function messagePrefix(): string;

    /**
     * The stable documentation URL for this rule (public API from 1.0).
     */
    public function documentationUrl(): string;

    /**
     * The suites this rule runs in — one of the four filter axes. Must be
     * non-empty: a rule belonging to no suite is a configuration error, enforced
     * by SuiteMembership, never a silent no-op. The same instance may run in
     * several suites (lint AND audit), so this is metadata, not an inheritance
     * tree.
     *
     * @return list<Suite>
     */
    public function suites(): array;

    /**
     * What this rule's verdict is ABOUT — and therefore where it can be placed.
     *
     * The audit suite addresses ONE instance, and a verdict scoped to the instance's write path
     * cannot be given on a replica: the value reads fine there and describes the wrong machine.
     * Declared by the rule because its author is the one who knows what the rule is talking about;
     * guessing it per finding would put the most confident possible wrong answer in a report.
     *
     * The lint suite never addresses an instance at all, so the value is not consulted for a rule
     * that only lints — but it is still declared, and declared conservatively, so that a lint rule
     * later admitted to the audit suite does not silently become cluster-valid on the way in.
     */
    public function instanceScope(): InstanceScope;

    /**
     * Whether this rule applies to the given subject. Side-effect free, never
     * throws, touches no database. A subject it does not apply to produces NO
     * finding — "not applicable" is silence, not a pass.
     */
    public function appliesTo(Subject $subject): bool;

    /**
     * Evaluate the subject and return the findings. Side-effect free with respect
     * to the database (no connection, no write, no lock). A subject that applies
     * but cannot be evaluated yields an undetermined finding with a named reason,
     * never an empty result.
     *
     * @return list<Finding>
     */
    public function evaluate(Subject $subject): array;
}
