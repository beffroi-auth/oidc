<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\InvalidArgumentException;

final readonly class InventoriedClient
{
    /**
     * @param non-empty-string $source
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $source,
        public string $clientId,
        public ?string $clientName = null,
        public ?DateTimeImmutable $registeredAt = null,
        public ?DateTimeImmutable $lastUsedAt = null,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('A client of a tenant carries the identifier it is known by (RFC 7591 section 2).');
        }
        if ($registeredAt !== null && $lastUsedAt !== null && $lastUsedAt < $registeredAt) {
            throw new InvalidArgumentException('A client was not used before it was registered.');
        }
    }

    public function wasRegisteredHere(): bool
    {
        return $this->registeredAt !== null;
    }
}
