<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Port\SubjectIdentifierKindInterface;

/**
 * OIDC Core §8 "public": every client sees the subject as the core keeps it (decision 0002).
 *
 * The way back is the same identifier read as itself, which is what it has always been: the string a client
 * presents is the one the provider keeps, so the user is the one that string names. It demands nothing of a
 * registration, this kind being computed from nothing a client registers.
 */
final readonly class PublicSubjectIdentifierResolver implements SubjectIdentifierKindInterface
{
    public const string SUBJECT_TYPE = 'public';

    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    public function subjectType(): string
    {
        return self::SUBJECT_TYPE;
    }

    public function resolve(User $user, Client $client): Subject
    {
        return $user->subject;
    }

    public function findUser(Client $client, Subject $subject): ?User
    {
        return $this->users->findBySubject($client->tenant, $subject);
    }

    public function assertAssignable(ClientRegistration $registration): void
    {
    }
}
