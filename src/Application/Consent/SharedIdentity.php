<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Consent;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;

/**
 * OIDC Core §8, decision 0006
 *
 * A client is told who a person is only when an authorization of it would name her without asking her anything.
 */
final readonly class SharedIdentity
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
    ) {
    }

    public function isSharedWith(User $user, Client $client): bool
    {
        return ! $client->registration->requiresConsent || $this->consents->findActive($user, $client) !== null;
    }
}
