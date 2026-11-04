<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;

interface ServedDeliveryModesInterface
{
    /**
     * @return list<DeliveryModeInterface>
     */
    public function servedDeliveryModes(): array;

    /**
     * @throws InvalidArgumentException
     */
    public function named(string $name): DeliveryModeInterface;
}
