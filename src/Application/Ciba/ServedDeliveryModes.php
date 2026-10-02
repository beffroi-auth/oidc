<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function array_values;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedDeliveryModesInterface;
use function sprintf;

/**
 * The delivery modes the wiring gave this provider, in the order they are wired (CIBA Core §4). The one
 * source of truth over them: the discovery document reads this list to know what to announce, and a
 * registration reads it to know what a client may name. A mode wired twice is refused here, where the
 * wiring is collected.
 */
final readonly class ServedDeliveryModes implements ServedDeliveryModesInterface
{
    /**
     * @param iterable<DeliveryModeInterface> $modes
     */
    public function __construct(
        private iterable $modes,
    ) {
    }

    public function servedDeliveryModes(): array
    {
        return array_values($this->wired());
    }

    public function named(string $name): DeliveryModeInterface
    {
        return $this->wired()[$name] ?? throw new InvalidArgumentException(sprintf(
            'The backchannel token delivery mode "%s" is not one this provider is wired with.',
            $name,
        ));
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return array<string, DeliveryModeInterface> by the name each mode gives itself
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->modes as $mode) {
            $name = $mode->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('The backchannel token delivery mode "%s" is wired twice.', $name));
            }
            $wired[$name] = $mode;
        }

        return $wired;
    }
}
