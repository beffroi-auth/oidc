<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Port\SubjectIdentifierKindInterface;

/**
 * OIDC Core §8
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
        return $this->open($client)->subjectOf($user);
    }

    public function open(Client $client): OpenedPublicSubjectIdentifier
    {
        return new OpenedPublicSubjectIdentifier();
    }

    public function findUser(Client $client, Subject $subject): ?User
    {
        return $this->users->findBySubject($client->tenant, $subject);
    }

    public function assertAssignable(ClientRegistration $registration): void
    {
    }
}
