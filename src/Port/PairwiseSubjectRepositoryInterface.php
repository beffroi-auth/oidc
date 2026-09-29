<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Claims\PairwiseSubject;
use Heidi\Oidc\Domain\Claims\SectorIdentifier;

/**
 * What each sector of a tenant has seen a user under (OIDC Core §8.1). The identifier is computed and not
 * drawn, so this keeps nothing the computation needs; what it keeps is what the computation cannot undo, the
 * user a recorded identifier belongs to.
 */
interface PairwiseSubjectRepositoryInterface
{
    /**
     * Null when this sector of this tenant has never been written a document about anybody under that
     * identifier, which is what a "sub" of another sector looks like from here.
     */
    public function findUser(Tenant $tenant, SectorIdentifier $sector, Subject $subject): ?User;

    /**
     * Records the identifier assigned to a user for a sector. It is written once and the same value is
     * written again at every document afterwards, so a second call for the same user and the same sector
     * changes nothing and races with itself harmlessly.
     */
    public function record(PairwiseSubject $assigned): void;
}
