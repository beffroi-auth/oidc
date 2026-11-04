<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use Stringable;

/**
 * OIDC Core §8.1
 */
final readonly class SectorIdentifier implements Stringable
{
    public function __construct(
        public string $host,
    ) {
        if ($host === '') {
            throw new InvalidArgumentException('A sector identifier is a host.');
        }
    }

    public function equals(self $other): bool
    {
        return $this->host === $other->host;
    }

    public function __toString(): string
    {
        return $this->host;
    }
}
