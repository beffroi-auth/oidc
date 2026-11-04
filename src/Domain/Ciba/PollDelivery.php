<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

/**
 * CIBA Core §10.1
 */
final readonly class PollDelivery implements DeliveryModeInterface
{
    public const string NAME = 'poll';

    public function name(): string
    {
        return self::NAME;
    }
}
