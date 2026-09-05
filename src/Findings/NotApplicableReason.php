<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * Why a check does not apply to this instance at all.
 *
 * ## Why this is not an UndeterminedReason
 *
 * "The provider enforces TLS outside the server configuration" and "I was not allowed to read the
 * catalog" are different facts about a run, and putting them in one enum would soften the
 * distinction in the type before any reporter ever saw it. An undetermined result is a check that
 * WANTED to run and could not; a not-applicable result is a check that had nothing to run against.
 *
 * The practical difference is `--strict`, which escalates the first and must not escalate the
 * second. A shared enum would make that a convention rather than a property.
 *
 * ## Why every case carries a description
 *
 * A not-applicable result is the one state a reader is most likely to skim past, because it looks
 * like nothing happened. What makes it honest rather than a silent pass is the sentence saying what
 * was not checked and why — so the reason is mandatory at the type level, exactly as it is for
 * {@see UndeterminedReason}.
 */
enum NotApplicableReason: string
{
    /**
     * The engine has no such concept, so there is nothing on this server the check could look at.
     *
     * MySQL has no row-level security and no per-routine search path; PostgreSQL's host-based
     * authentication file has no MySQL equivalent. Today those rules answer with SILENCE, which a
     * reader takes for "checked and fine" — the exact silent pass this package exists to refuse.
     */
    case EngineLacksConstruct = 'engine_lacks_construct';

    /**
     * The platform decides the setting above the server, so the server's own value cannot answer.
     *
     * A managed provider that terminates TLS at its proxy makes `ssl = off` in the server
     * configuration say nothing about whether connections are encrypted. Reporting the setting
     * would be a finding about the wrong layer; reporting a pass would claim a property nobody
     * verified.
     */
    case ProviderEnforced = 'provider_enforced';

    /**
     * The project was asked and answered that the construct is not how it solves this.
     *
     * `security.rls.mode = off` is the case it exists for, and the reason it needed a case of its own
     * is that the rule's own remediation OFFERS it: *set the mode to off — that is an answer SQLens can
     * record, and a guess it will not make.* A project that follows that sentence has said something
     * true about its database, and the report has to be able to show the difference between having
     * answered and never having been asked. Otherwise the one line saying "tenant separation was not
     * checked" is unclosable, and a finding nobody can close is one everybody learns to skip.
     *
     * Not an {@see UndeterminedReason}, and the distinction is the one this enum is built on: nothing
     * was undecided here. The question was put and answered.
     */
    case DeclinedByProject = 'declined_by_project';

    /** What a reader is told, in the report, about what was not checked here. */
    public function description(): string
    {
        return match ($this) {
            self::EngineLacksConstruct => 'This engine has no such concept, so there is nothing here for the check to look at; the rule is reported rather than left silent, because silence reads as a pass.',
            self::ProviderEnforced => 'The platform decides this above the server, so the server\'s own setting cannot answer the question; what the provider enforces is outside what this run can read.',
            self::DeclinedByProject => 'The project declared in its configuration that this construct is not how it solves the problem, so there is nothing here to judge; reported rather than left silent, because a question that was answered should read differently from one that was never asked.',
        };
    }
}
