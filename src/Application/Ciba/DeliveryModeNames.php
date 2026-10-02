<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function array_map;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;

/**
 * The names of delivery modes, read from the modes themselves. Every place that has to say them, the
 * discovery document and the message a registration naming an unwired mode is refused with, reads them
 * here: a mode names itself and nothing writes that reading again.
 */
final readonly class DeliveryModeNames
{
    /**
     * @param list<DeliveryModeInterface> $modes
     *
     * @return list<string>
     */
    public static function of(array $modes): array
    {
        return array_map(static fn (DeliveryModeInterface $mode): string => $mode->name(), $modes);
    }
}
