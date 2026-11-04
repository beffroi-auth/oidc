<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use DateInterval;
use DateTimeImmutable;

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
