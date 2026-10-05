<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * A driver canonicalization that knows which words its server refuses as a bare name.
 *
 * Kept apart from {@see DriverCanonicalization::keywords()} on purpose. That list is what the
 * keyword-casing stage folds, the words the canonicalizer reads in a statement. This one is the
 * server's own reserved set, and the canonical form quotes a name from it, so that a name which
 * reaches a suggestion or a remediation still parses when a reader pastes it back. The two sets
 * overlap without either containing the other.
 *
 * A separate contract rather than a method on {@see DriverCanonicalization}, so a canonicalization
 * registered through the extension registry keeps working unchanged. One that does not declare
 * the set is read as it always was: its keywords are quoted, and nothing else.
 */
interface DeclaresReservedWords
{
    /**
     * Every word the server reserves, upper case.
     *
     * @return list<string>
     */
    public function reservedWords(): array;
}
