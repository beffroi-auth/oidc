<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use DateTimeImmutable;

/**
 * Where what a client was given of a person is written down and forgotten again (issue #590). Both are
 * writes, which is why they are one port; reading them is another (DisclosuresOfAPersonInterface).
 *
 * The write is a message and not a step of a request, unlike the history of a record: what it is written
 * from is an act, and an act travels the lane the events travel (architecture §5.6), so a row that cannot
 * be written does not undo what was done. What holds the two together is the duration, which is the
 * journal's: an act whose row is gone, or a row whose act is gone, is half an answer.
 */
interface DisclosuresInterface
{
    public function record(Disclosure $disclosure): void;

    /**
     * Forgets what was given to a client of this tenant before the moment given, and says how many rows it
     * forgot. Bounded by the implementation, so a backlog is worked through over several runs.
     */
    public function forgetBefore(Tenant $tenant, DateTimeImmutable $moment): int;
}
