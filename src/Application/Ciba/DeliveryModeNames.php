<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function array_map;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;

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
