<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Disclosure;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * How long what a client was given of a person is kept, and what forgets the rows past it (issue #590).
 *
 * **The duration is the journal's**, read from the one place a deployment names it: a row of this register
 * and the act that announced it are two halves of one answer, so keeping one longer than the other leaves
 * an act whose row is gone, or a row whose act is gone. A deployment that moves one moves both because
 * there is one duration and not two.
 *
 * It says how many it forgot, so the timed step that forgets the acts can say whether it did anything, and
 * the store bounds a run so that a backlog is worked through over several ticks.
 */
final readonly class DisclosureRetention
{
    public function __construct(
        private DisclosuresInterface $disclosures,
        private ClockInterface $clock,
        private int $days,
    ) {
    }

    public function enforce(Tenant $tenant): int
    {
        return $this->disclosures->forgetBefore($tenant, $this->clock->now()->modify(sprintf('-%d days', $this->days)));
    }
}
