<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;

/**
 * Where a shadow capture leaves what its setup said for a person, beyond what the results carry, for
 * the command that ran it.
 *
 * Two kinds of sentence arrive here. A provisioner that stops before it creates anything names a
 * reason, which every result of the run carries, and often a detail beside it: the sessions holding
 * the PostgreSQL template, the line of a MySQL dump that could not be split. A provisioner that
 * succeeded can leave a note about what it did not replay, such as a dump directive that set the SQL
 * mode. The results keep neither, because part of such a sentence differs from one run to the next
 * and the results must not. The command writes them on STDERR instead, where a person reading the
 * run finds them.
 *
 * It travels beside the capture run for the reason {@see ShadowSweepRecorder} gives: the run passes
 * through decorators that each build a new one.
 */
final class ShadowNoteRecorder
{
    /** @var list<string> */
    private array $notes = [];

    /** Keep the refusal's sentence for a person, once, when it says more than its reason. */
    public function refused(ShadowProvisioningUndetermined $refusal): void
    {
        $sentence = $refusal->forAPerson();

        if ($sentence !== null) {
            $this->noted($sentence);
        }
    }

    /** Keep a note the setup left, once. */
    public function noted(string $note): void
    {
        if (! in_array($note, $this->notes, true)) {
            $this->notes[] = $note;
        }
    }

    /**
     * What the setup of this run said, in the order it came.
     *
     * @return list<string>
     */
    public function notes(): array
    {
        return $this->notes;
    }
}
