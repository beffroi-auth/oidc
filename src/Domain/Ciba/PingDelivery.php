<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Ciba;

/**
 * CIBA Core §10.2: the provider posts the identifier of the request to the endpoint the client
 * registered, with the token that client sent, and the client then comes to the token endpoint as a
 * poller does. Tokens are never carried there: what the notification says is that there is something to
 * come and get, and the token endpoint is the only place this provider ever hands one out (§10.3 is not
 * served, decision 0006).
 */
final readonly class PingDelivery implements NotifiesTheClientInterface
{
    public const string NAME = 'ping';

    public function name(): string
    {
        return self::NAME;
    }
}
