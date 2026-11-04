<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

/**
 * CIBA Core §10
 */
interface DeliveryModeInterface
{
    public function name(): string;
}
