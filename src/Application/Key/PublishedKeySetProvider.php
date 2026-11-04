<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksCacheInterface;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use Psr\Clock\ClockInterface;

/**
 * RFC 7517 §5, RFC 7591 §2
 *
 * A kept set is filed under its URL alone, so a party that moves its keys is read again at once.
 */
final readonly class PublishedKeySetProvider
{
    public function __construct(
        private ClientJwksFetcherInterface $fetcher,
        private ClientJwksCacheInterface $cache,
        private ClockInterface $clock,
        private DateInterval $cooldown,
    ) {
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    public function keysOf(ClientJwks|ClientUri $published, ?string $keyId): ClientJwks
    {
        if ($published instanceof ClientJwks) {
            return $published;
        }
        $kept = $this->cache->read($published);
        if ($kept === null) {
            return $this->readAndKeep($published);
        }
        $now = $this->clock->now();
        if ($keyId !== null && ! $kept->holds($keyId) && $now >= $kept->mayBeFetchedAgainAt($this->cooldown)) {
            return $this->readAndKeep($published);
        }

        return $kept->keys;
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    private function readAndKeep(ClientUri $jwksUri): ClientJwks
    {
        $keys = $this->fetcher->fetch($jwksUri);
        $this->cache->write($jwksUri, new CachedClientJwks($keys, $this->clock->now()));

        return $keys;
    }
}
