<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\ClientInventory;
use Beffroi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\ClientRemovalRefusedException;
use Beffroi\Oidc\Port\ClientStoreInterface;

/**
 * A client of the tenant deleted by an administrator through the administration API (decision 0038), on the use case
 * `beffroi:client:delete` calls: a client registered here only, and the act names the administrator.
 */
final readonly class AdministeredClientRemoval
{
    public function __construct(
        private ClientInventory $clients,
        private ClientStoreInterface $store,
        private RegisteredClientRemoval $removal,
    ) {
    }

    /**
     * @throws ClientRemovalRefusedException when the deployment declares the client, or the administrator acts through it
     *
     * @return bool false when the tenant has no client of that identifier
     */
    public function remove(ActingAdministrator $administrator, string $clientId, RequestContext $context): bool
    {
        if ($clientId === $administrator->clientId) {
            throw ClientRemovalRefusedException::actedThrough($clientId);
        }
        $client = $this->clients->find($administrator->tenant, $clientId);
        if ($client === null) {
            return false;
        }
        if (! $client->wasRegisteredHere()) {
            throw ClientRemovalRefusedException::declared($clientId);
        }
        $record = $this->store->findRecord($administrator->tenant, $clientId);
        if ($record === null) {
            return false;
        }
        $this->removal->removeByAnAdministrator($record, $administrator->user->subject, $context);

        return true;
    }
}
