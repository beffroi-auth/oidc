<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;

/**
 * A token naming no person is read by its "sub", for its own client and never as a row key (OIDC Core §8).
 */
final readonly class PersonOfAnAccessToken
{
    public function __construct(
        private UserRepositoryInterface $users,
        private PresentedSubjectReaderInterface $subjects,
    ) {
    }

    public function of(VerifiedAccessToken $token): ?User
    {
        $person = $token->person;

        return $person === null
            ? $this->subjects->findUser($token->client, $token->subject)
            : $this->users->findBySubject($token->client->tenant, $person);
    }
}
