<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use DateInterval;
use DateTimeImmutable;

/**
 * The last read of a published set: what it answered, or the set kept from a read before it, or nothing when no read
 * has answered yet.
 */
final readonly class CachedClientJwks
{
    public function __construct(
        public ?ClientJwks $keys,
        public DateTimeImmutable $readAt,
    ) {
    }

    public function holds(string $keyId): bool
    {
        return $this->keys?->holds($keyId) ?? false;
    }

    public function mayBeReadAgainAt(DateInterval $cooldown): DateTimeImmutable
    {
        return $this->readAt->add($cooldown);
    }
}
