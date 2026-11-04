<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Oidc\Domain\Consent\Consent;

interface CanPageActiveConsentsInterface
{
    /**
     * @param Period|null $period when they were granted, all of them when null
     *
     * @return Listing<Consent> most recently granted first
     */
    public function pageOfActiveConsents(User $user, Pagination $pagination, ?Period $period = null): Listing;
}
