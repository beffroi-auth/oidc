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
use DateTimeInterface;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * RFC 7517 §5, RFC 7591 §2
 *
 * A kept set is filed under its URL alone, so a party that moves its keys is read again at once. A read that failed is
 * kept too: a URL is read at most once per cooldown, whoever names it and whether it answers or not.
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
            return $this->readAndKeep($published, null);
        }
        $mayReadAgain = $this->clock->now() >= $kept->mayBeReadAgainAt($this->cooldown);
        if ($kept->keys === null) {
            if (! $mayReadAgain) {
                throw new ClientKeysUnavailableException(sprintf(
                    '%s could not be read at %s, and is not read again before %s.',
                    $published->value,
                    $kept->readAt->format(DateTimeInterface::ATOM),
                    $kept->mayBeReadAgainAt($this->cooldown)->format(DateTimeInterface::ATOM),
                ));
            }

            return $this->readAndKeep($published, null);
        }
        if ($keyId !== null && ! $kept->holds($keyId) && $mayReadAgain) {
            return $this->readAndKeep($published, $kept->keys);
        }

        return $kept->keys;
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    private function readAndKeep(ClientUri $jwksUri, ?ClientJwks $held): ClientJwks
    {
        $now = $this->clock->now();
        try {
            $keys = $this->fetcher->fetch($jwksUri);
        } catch (ClientKeysUnavailableException $exception) {
            $this->cache->write($jwksUri, new CachedClientJwks($held, $now));

            throw $exception;
        }
        $this->cache->write($jwksUri, new CachedClientJwks($keys, $now));

        return $keys;
    }
}
