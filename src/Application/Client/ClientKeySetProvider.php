<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use DateInterval;
use Heidi\Oidc\Domain\Client\CachedClientJwks;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Port\ClientJwksCacheInterface;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;
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
