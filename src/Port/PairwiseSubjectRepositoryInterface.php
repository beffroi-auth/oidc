<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Claims\PairwiseSubject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;

interface PairwiseSubjectRepositoryInterface
{
    public function findUser(Tenant $tenant, SectorIdentifier $sector, Subject $subject): ?User;

    /**
     * Idempotent: a second call for the same user and the same sector changes nothing, even concurrently.
     */
    public function record(PairwiseSubject $assigned): void;
}
