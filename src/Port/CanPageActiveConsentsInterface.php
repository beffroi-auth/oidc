<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Consent\ConsentQuestion;

interface CanPageActiveConsentsInterface
{
    /**
     * @return Listing<Consent> most recently granted first
     */
    public function pageOfActiveConsents(User $user, ConsentQuestion $question, Pagination $pagination): Listing;
}
