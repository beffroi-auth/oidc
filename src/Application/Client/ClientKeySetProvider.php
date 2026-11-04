<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use function sprintf;

final readonly class ClientKeySetProvider
{
    public function __construct(
        private PublishedKeySetProvider $keys,
    ) {
    }

    /**
     * @throws ClientAuthenticationFailure when the keys of the client cannot be read
     */
    public function keysAuthenticating(Client $client, ?string $keyId, ClientAuthenticationMethodInterface $method): ClientJwks
    {
        try {
            return $this->keysOf($client, $keyId);
        } catch (ClientKeysUnavailableException $exception) {
            throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::UnreadableClientKeys,
                $client->registration->clientId,
                $method->name(),
                $exception->getMessage(),
                $exception,
            );
        }
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    public function keysOf(Client $client, ?string $keyId): ClientJwks
    {
        $published = $client->registration->publishedKeys();
        if ($published === null) {
            throw new ClientKeysUnavailableException(sprintf('The client "%s" publishes no key.', $client->registration->clientId));
        }

        return $this->keys->keysOf($published, $keyId);
    }
}
