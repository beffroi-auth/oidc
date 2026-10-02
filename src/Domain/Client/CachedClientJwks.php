<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use DateInterval;
use DateTimeImmutable;

/**
 * The keys read back from a client's "jwks_uri" and the moment they were read. The moment is what the
 * cooldown is counted from: an unknown "kid" is worth one fetch, and a client that signs with a key it
 * never published cannot make the provider call it on every request.
 */
final readonly class CachedClientJwks
{
    public function __construct(
        public ClientJwks $keys,
        public DateTimeImmutable $fetchedAt,
    ) {
    }

    public function holds(string $keyId): bool
    {
        return $this->keys->holds($keyId);
    }

    public function mayBeFetchedAgainAt(DateInterval $cooldown): DateTimeImmutable
    {
        return $this->fetchedAt->add($cooldown);
    }
}
