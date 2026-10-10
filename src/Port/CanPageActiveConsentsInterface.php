<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Oidc\Domain\Consent\Consent;

/**
 * A companion of ActiveConsentsInterface: one page of what a person has agreed to, for the table of their
 * account where they read it and take one back (architecture §5.2).
 */
interface CanPageActiveConsentsInterface
{
    /**
     * @return Listing<Consent> the ones in force, most recently granted first; one given to a client no
     *                          longer registered is not listed, as it is not in the whole list either
     */
    public function pageOfActiveConsents(User $user, Pagination $pagination): Listing;
}
