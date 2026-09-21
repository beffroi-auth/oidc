<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Client\Client;

/**
 * Remembers the "jti" of a client assertion until the assertion expires (RFC 7523 §3, §4), so that one
 * assertion authenticates once. The store outlives the request and is shared by the workers of a
 * deployment: an assertion replayed on another worker is a replay all the same.
 */
interface ClientAssertionReplayGuardInterface
{
    /**
     * @param string $jti the identifier of the assertion, unique to the client that issued it
     * @param DateTimeImmutable $expiresAt when the assertion stops being valid, after which it may be forgotten
     *
     * @return bool true when the identifier had not been seen and is now remembered, false when it had
     */
    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool;
}
