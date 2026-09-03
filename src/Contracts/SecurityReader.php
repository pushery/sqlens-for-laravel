<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\Objects\GrantReading;
use Pushery\SQLens\Catalog\Objects\HbaReading;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Catalog\Objects\RoleReading;
use Pushery\SQLens\Catalog\Objects\RoutineReading;
use Pushery\SQLens\Catalog\Setting;

/**
 * What one engine can tell an audit about its own security state.
 *
 * It is a separate contract from {@see CatalogReader} rather than more methods on it, because the two
 * degrade completely differently. A catalog reading works on every managed database (measured:
 * `pg_class` and `pg_index` stay world-readable); a security reading is refused in pieces by design,
 * and half of it needs privileges a managed provider never hands out. Mixing them would put "this
 * ordinarily fails" and "this ordinarily works" behind one interface, and the caller would have to
 * know which method it was calling to know how to read an empty answer.
 *
 * ## Why this interface grows one method at a time
 *
 * The obvious shape is all six areas at once — settings, roles, grants, routines, HBA rules, RLS
 * state. It is not what this declares, deliberately: a method whose implementation is not built yet
 * can only answer with a placeholder, and a placeholder that says "undetermined" is a check
 * reporting that it could not run when in truth nobody wrote it. That is the exact silent green this
 * package exists against, dressed as compliance with its own three-valued rule.
 *
 * So each area is declared here in the change that implements it on BOTH engines, and until then it
 * is absent — which no reader can misreport. The order is one area per change, each proven on both engines before the next is declared.
 *
 * ## Settings are absent for a different reason
 *
 * They are already read: {@see ServerSettingsReader} returns {@see Setting}
 * objects carrying scope, source and pending-restart, which is strictly more than a security reading
 * needs. A second settings path would be two answers to "what is `password_encryption`", and the
 * interesting version of that question — which of the two a report shows — has no good answer. The
 * security rules read that reader.
 */
interface SecurityReader
{
    /**
     * Every account this server has, with the reason for anything missing.
     *
     * Never an empty list standing in for a refusal: on MySQL `mysql.user` answers `1142` to an
     * account without `SELECT ON mysql.*`, and returning `[]` there would report a server with no
     * users at all. The refusal becomes a named skip on the reading.
     */
    public function roles(): RoleReading;

    /**
     * Who may do what on this server, with the reason for anything missing.
     *
     * The two engines make this the same question in opposite ways, which is why it is one method:
     * PostgreSQL keeps its ACLs on the objects themselves and world-readable — measured, a plain
     * application role sees exactly what a superuser does — while MySQL keeps them in the `mysql`
     * schema behind a privilege, and refuses without it.
     *
     * `information_schema.SCHEMA_PRIVILEGES` is deliberately not read as a substitute after that
     * refusal: it never errors, it silently narrows to what the caller may see, so it would turn a
     * refusal into a confident wrong answer.
     */
    public function grants(): GrantReading;

    /**
     * The row-level security state of the tables this project asked about.
     *
     * The scope is the project's, not ours: "which tables hold tenant data" is a question only the
     * application can answer, and checking every table would report every reference table and job
     * queue in the schema. An unconfigured project gets an EMPTY reading that says so — see
     * {@see RlsReading::unconfigured()} — which the rules turn into one `undetermined` naming the key.
     *
     * MySQL has no row-level security, so its reader answers with the same empty-and-says-so reading
     * rather than pretending the question applies.
     */
    public function rlsStates(): RlsReading;

    /**
     * The host-based authentication rules the server is running, in the order it evaluates them.
     *
     * Declared now because BOTH engines answer it, which is what this interface requires before a
     * method may exist — and the two answers are deliberately different KINDS of answer rather than
     * one real and one placeholder. PostgreSQL reads `pg_hba_file_rules`, which refuses `42501` to
     * anything short of superuser or `pg_read_all_settings`; that refusal becomes a named skip on the
     * reading, never an empty list, because an empty list would describe a server that lets nobody
     * in. MySQL has no such file and nothing shaped like it — its access control is the host pattern
     * on the account itself, which {@see self::roles()} already returns — so it answers
     * `HbaReading::unsupported()`.
     *
     * That third state is the point. "Ask somebody with more rights" and "the question does not apply
     * here" produce opposite reports, and a rule that could not tell them apart would emit an
     * `undetermined` on every MySQL run — the noise that gets a suite switched off.
     */
    public function hbaRules(): HbaReading;

    /**
     * The stored routines in scope, described by what they run AS.
     *
     * Both engines have the concept and both spell it the same way in substance: a routine may run
     * with its OWNER's privileges instead of its caller's. That is a deliberate and legitimate
     * construction — it is how a low-privilege application is given one narrow, audited path into
     * something it otherwise could not touch — and it turns into a privilege escalation the moment
     * the routine does not pin its own `search_path`. PostgreSQL then resolves the routine's
     * unqualified names through the CALLER's path, so a caller who can create a schema ahead of it
     * substitutes their own function and the routine calls it, as the owner.
     *
     * Which is why this is a reading of its own rather than a column on the grant reading. The grants
     * already say WHO may execute a routine; this says what executing it is worth, and the two are
     * only dangerous together.
     *
     * The body is deliberately not part of the answer, on the same terms as `pg_authid.rolpassword`
     * and `pg_hba_file_rules.options`: `prosrc` is the likeliest place in any catalog to hold a
     * credential, and this package judges posture rather than copying code.
     */
    public function routines(): RoutineReading;
}
