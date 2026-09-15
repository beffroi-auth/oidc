<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §8: "public" subject type, the one of spike 1. Every client sees the subject of the user as
 * the core keeps it (decision 0002: stable, never reassigned), whatever the client.
 */
final readonly class PublicSubjectIdentifierResolver implements SubjectIdentifierResolverInterface
{
    public function resolve(User $user, Client $client): Subject
    {
        return $user->subject;
    }
}
