<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The ways the provider is wired to tell a client that a backchannel request has been answered (CIBA
 * Core §4), the one source of truth over them: what the discovery document announces and what a client
 * may register in "backchannel_token_delivery_mode" read this one, so that they cannot disagree.
 */
interface ServedDeliveryModesInterface
{
    /**
     * @return list<DeliveryModeInterface> in the order they are wired
     */
    public function servedDeliveryModes(): array;

    /**
     * @throws InvalidArgumentException when the provider is wired with no mode of that name
     */
    public function named(string $name): DeliveryModeInterface;
}
