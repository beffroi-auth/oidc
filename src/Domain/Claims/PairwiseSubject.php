<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * The identifier one sector sees a user under (OIDC Core §8.1), recorded the first time a client of that
 * sector is written a document about them.
 *
 * It records a fact and does not decide one: the value is computed from the sector, the user and the salt of
 * the tenant, so the same three give it again whether or not this row exists. What the row is for is the way
 * back: a "sub" a client presents is a string no other table carries, and hashing is one way, so the one way
 * to answer "who is this, to this client" is to have written it down.
 */
final class PairwiseSubject
{
    public readonly Tenant $tenant;

    /**
     * On every entity the identifier is private(set), not readonly: a mapper building lazy references
     * assigns it twice.
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly SectorIdentifier $sector,
        public readonly Subject $subject,
        public readonly DateTimeImmutable $assignedAt,
    ) {
        $this->tenant = $user->tenant;
    }
}
