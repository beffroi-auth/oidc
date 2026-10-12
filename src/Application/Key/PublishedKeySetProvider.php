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
 * The public keys of a party whose signature this provider verifies, whichever way that party publishes
 * them (RFC 7517 §5, RFC 7591 §2). A set written down in the registration is the whole answer and
 * nothing is fetched. A set behind a URL is read once and kept; it is read again when the signature
 * names a "kid" the kept set does not hold, and then at most once per cooldown, which is the symmetric
 * of what Symfony's own client does since spike 2: a party that rotates a key is followed within one
 * request, and a party that signs with a key it never published cannot make the provider call it on
 * every request.
 *
 * Two parties publish keys this provider reads: a client (RFC 7591 §2) and an issuer a tenant trusts
 * (RFC 7523 §3). **This is the one class that reads a published set and keeps it**, and it is wired once
 * per family of publisher, each with a pool of its own, as the assertions of a client and those of an
 * issuer have one each: a deployment points one at a store its workers share without touching the other,
 * and a client cannot be verified against a set read for an issuer.
 *
 * **A kept set is filed under the URL it was read from** and under nothing else. That URL is what
 * identifies the document: two parties that publish behind the same URL publish the same keys and share
 * one read, and a party that moves its keys elsewhere is read again at once rather than verified against
 * what the URL it left still answered.
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
     * @param ClientJwks|ClientUri $published the set the party wrote down, or the URL it publishes it
     *                                        behind; one or the other and never both, which the type is
     * @param string|null $keyId the "kid" the signature names, null when it names none
     *
     * @throws ClientKeysUnavailableException when the keys cannot be read
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
