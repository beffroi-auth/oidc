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

/**
 * The keys of a client, whichever way it publishes them (RFC 7591 §2). What a client publishes is its
 * registration's to say and what reading a set behind a URL costs is PublishedKeySetProvider's, which
 * reads the keys of every party this provider verifies a signature of; this class is the client's half
 * of that reading: the set its registration names, and what being unable to read it means for the method
 * that was authenticating it.
 */
final readonly class ClientKeySetProvider
{
    public function __construct(
        private PublishedKeySetProvider $keys,
    ) {
    }

    /**
     * The keys of the client for a method that is authenticating it: keys that cannot be read are a
     * refusal of that method and not an error of the endpoint, and every method that verifies a
     * signature of a client refuses the same way (RFC 6749 §5.2).
     *
     * @param string|null $keyId the "kid" the signature names, null when it names none
     *
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
     * @param string|null $keyId the "kid" the signature names, null when it names none
     *
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
