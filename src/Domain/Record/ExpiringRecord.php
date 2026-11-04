<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Record;

use DateTimeImmutable;

abstract class ExpiringRecord
{
    abstract public DateTimeImmutable $expiresAt { get; }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
