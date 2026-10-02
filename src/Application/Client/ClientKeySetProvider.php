<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use DateInterval;
use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksCacheInterface;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The keys of a client, whichever way it publishes them (RFC 7591 §2). A set given inline is the whole
 * answer and nothing is fetched. A set behind a "jwks_uri" is fetched once and kept; it is fetched again
 * when the assertion names a "kid" the kept set does not hold, and then at most once per cooldown, which
 * is the symmetric of what Symfony's own client does since spike 2: a client that rotates a key is
 * followed within one request, and a client that signs with a key it never published cannot make the
 * provider call it on every request.
 */
final readonly class ClientKeySetProvider
{
    public function __construct(
        private ClientJwksFetcherInterface $fetcher,
        private ClientJwksCacheInterface $cache,
        private ClockInterface $clock,
        private DateInterval $cooldown,
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
        $inline = $client->registration->jwks;
        if ($inline !== null) {
            return $inline;
        }
        $jwksUri = $client->registration->jwksUri;
        if ($jwksUri === null) {
            throw new ClientKeysUnavailableException(sprintf('The client "%s" publishes no key.', $client->registration->clientId));
        }
        $kept = $this->cache->read($client);
        if ($kept === null) {
            return $this->fetchAndKeep($client, $jwksUri);
        }
        $now = $this->clock->now();
        if ($keyId !== null && ! $kept->holds($keyId) && $now >= $kept->mayBeFetchedAgainAt($this->cooldown)) {
            return $this->fetchAndKeep($client, $jwksUri);
        }

        return $kept->keys;
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    private function fetchAndKeep(Client $client, ClientUri $jwksUri): ClientJwks
    {
        $keys = $this->fetcher->fetch($jwksUri);
        $this->cache->write($client, new CachedClientJwks($keys, $this->clock->now()));

        return $keys;
    }
}
