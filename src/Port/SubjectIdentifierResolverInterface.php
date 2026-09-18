<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;

/**
 * The "sub" a client sees for a user (OIDC Core §8); every token and UserInfo response go through it (§5.3.2).
 */
interface SubjectIdentifierResolverInterface
{
    public function resolve(User $user, Client $client): Subject;
}
