<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;

/**
 * A client is kept when used since $usedSince or, never used, registered since $registeredSince.
 */
final readonly class ClientRetention
{
    public function __construct(
        public DateTimeImmutable $usedSince,
        public DateTimeImmutable $registeredSince,
    ) {
    }
}
