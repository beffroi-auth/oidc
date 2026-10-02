<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * Remembers the "jti" of a request object until the object expires (CIBA Core §7.1.1), so that one
 * signed request is made once. The store outlives the request and is shared by the workers of a
 * deployment: an object replayed on another worker is a replay all the same.
 */
interface RequestObjectReplayGuardInterface
{
    /**
     * @param string $jti the identifier of the object, unique to the client that signed it
     * @param DateTimeImmutable $expiresAt the "exp" of the object, after which it may be forgotten
     *
     * @return bool true when the identifier had not been seen and is now remembered, false when it had
     */
    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool;
}
