<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §8 "public": every client sees the subject as the core keeps it (decision 0002).
 */
final readonly class PublicSubjectIdentifierResolver implements SubjectIdentifierResolverInterface
{
    public function subjectType(): string
    {
        return 'public';
    }

    public function resolve(User $user, Client $client): Subject
    {
        return $user->subject;
    }
}
