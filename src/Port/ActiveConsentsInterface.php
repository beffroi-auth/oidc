<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;

/**
 * A companion of ConsentRepositoryInterface: what a user has agreed to, for the page of the account where
 * they read it and take one back (architecture §5.2).
 */
interface ActiveConsentsInterface
{
    /**
     * @return list<Consent> the ones in force, most recently granted first; one given to a client no longer
     *                       registered is not listed, as no store here lists a record of an absent client
     */
    public function activeOf(User $user): array;
}
