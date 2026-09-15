<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;

/**
 * The "sub" a client sees for a user (OIDC Core §8). A public subject is the same for every client; a
 * pairwise one (§8.1) is computed per sector and comes later. Every token and the UserInfo response of
 * one user for one client go through the same resolver, so that they name the same subject (§5.3.2).
 */
interface SubjectIdentifierResolverInterface
{
    public function resolve(User $user, Client $client): Subject;
}
