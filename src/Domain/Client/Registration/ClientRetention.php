<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;

/**
 * What a tenant still keeps of the clients that registered themselves, at one instant (decision 0009): two
 * dates, because a client that was used and a client that never was are not worth the same. A client used
 * before the first is dropped; a client that was never used and registered before the second is dropped.
 *
 * Two dates and not two durations, because that is what a store can ask its rows: a purge that had to read
 * every row to subtract a duration from the instant would be a purge that reads the table it is there to
 * keep small.
 */
final readonly class ClientRetention
{
    public function __construct(
        public DateTimeImmutable $usedSince,
        public DateTimeImmutable $registeredSince,
    ) {
    }
}
