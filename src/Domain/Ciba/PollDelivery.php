<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

/**
 * CIBA Core §10.1: the client asks the token endpoint again and again until the request has been
 * answered. Nothing leaves the provider for the client, which is why this is the mode a client takes
 * when it registers one and nothing else is needed of it.
 */
final readonly class PollDelivery implements DeliveryModeInterface
{
    public const string NAME = 'poll';

    public function name(): string
    {
        return self::NAME;
    }
}
