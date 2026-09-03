<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * One rule in the Postgres Language Server's security catalog, as this package measured it.
 *
 * The NAME, the SEVERITY and the help link came out of the tool: the catalog is executed as a
 * single SQL statement in which each rule carries its own `-- meta:` header, so those are measured
 * facts rather than a reading of a website. A list copied from documentation is a list of what the
 * documentation says, not of what the installed binary runs.
 *
 * The SUMMARY is this package's own sentence. The tool's title and description are its authors'
 * prose, and reproducing them here would contradict the NOTICE's own promise that no wording from
 * an external manual is carried.
 */
final readonly class PglsRule
{
    public function __construct(
        /** The short rule name, e.g. `functionSearchPathMutable`. */
        public string $rule,
        public PglsSeverity $severity,
        /**
         * What the rule is about, in THIS package's words.
         *
         * Deliberately not the tool's own title and description, which is what an earlier draft
         * shipped. Those are somebody else's prose, and this package's NOTICE says plainly that no
         * wording from an external manual is reproduced — a rule NAME and a severity are facts, and
         * facts carry no license; a sentence explaining the rule is authorship.
         */
        public string $summary,
        /**
         * Where the rule is documented — the link the TOOL carries in its own catalog, not one
         * this package composed. It points outside this project, which is why a finding built
         * from it has to be marked as external: a reader who follows it lands in somebody else's
         * documentation, and a help link that quietly does that is a small betrayal.
         */
        public string $helpUri,
    ) {}
}
