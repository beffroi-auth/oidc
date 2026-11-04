<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * OIDC Core §8
 */
interface SubjectIdentifierResolverInterface
{
    /**
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind this client registered
     */
    public function resolve(User $user, Client $client): Subject;
}
