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

    /**
     * Nothing is pending, so there is no change for this check to judge the state against.
     *
     * The deploy-context checks are the case: `lock_timeout = 0` matters BECAUSE a migration is
     * about to run behind whatever is holding a lock, and with nothing pending that sentence is
     * false. A consumer ran the gate after a deploy and read three findings arguing from a
     * migration in the same report whose first line said none had been read — a gate that refutes
     * its own premise teaches a reader to take the next real red for noise.
     *
     * The state is still reported, with its value; what is withheld is the verdict.
     */
    case NothingPending = 'nothing_pending';

    /**
     * The project declared that this server does not outlive the run, so its own configuration is a
     * fixture rather than a deployment.
     *
     * The case a pipeline needs, and the one that had a lane deciding which of this package's blocks
     * count. Measured before it existed: `sqlens:audit --profile=ci` against a freshly migrated
     * schema ended at exit 3 on four `SEC.AUTH.HBA_TRUST`, one `SEC.PRIV.ROLE_SUPERUSER` and one
     * `SEC.CFG.TLS_DISABLED` — every one of them about a container the job creates and destroys,
     * none of them about the application the job is there to judge.
     *
     * ⚠️ **It withholds a verdict about the SERVER and nothing else.** Every schema finding reports
     * unchanged, because the schema is what gets deployed onto a real host and the declaration says
     * nothing about it. And the withheld checks are not dropped: they are what `sqlens:predeploy`
     * runs against the target host, where the same facts are real — so the finding names that
     * command rather than merely going quiet.
     *
     * Not {@see DeclinedByProject}, though both come from configuration, and the difference is worth
     * the second case: that one says "this construct is not how we solve the problem", an answer
     * about the DESIGN that holds wherever the code runs. This one says "the thing you are looking
     * at is not the thing that will be operated", an answer about THIS RUN — the identical project,
     * audited on its target host, gets the verdict back.
     */
    case ServerIsDisposable = 'server_is_disposable';

    /** What a reader is told, in the report, about what was not checked here. */
    public function description(): string
    {
        return match ($this) {
            self::EngineLacksConstruct => 'This engine has no such concept, so there is nothing here for the check to look at; the rule is reported rather than left silent, because silence reads as a pass.',
            self::ProviderEnforced => 'The platform decides this above the server, so the server\'s own setting cannot answer the question; what the provider enforces is outside what this run can read.',
            self::NothingPending => 'No migration is pending in this run, so there is no change for this to be judged against; the setting and its value are reported, and the verdict is not — the same run would judge it the moment something is actually about to run.',
            self::DeclinedByProject => 'The project declared in its configuration that this construct is not how it solves the problem, so there is nothing here to judge; reported rather than left silent, because a question that was answered should read differently from one that was never asked.',
            self::ServerIsDisposable => 'The project declared that this server does not outlive the run, so its own configuration describes a fixture rather than a deployment; the schema is judged exactly as it would be anywhere, and the server facts this withholds are the ones sqlens:predeploy reads on the host that will actually be operated.',
        };
    }
}
