<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

/**
 * CIBA Core §10.2
 */
final readonly class PingDelivery implements NotifiesTheClientInterface
{
    public const string NAME = 'ping';

    public function name(): string
    {
        return self::NAME;
    }
}
