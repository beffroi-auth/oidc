<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Exception\InvalidArgumentException;

interface FlowPicturesInterface
{
    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     *
     * @return non-empty-list<FlowPicture>
     */
    public function pictures(): array;

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function of(GrantTypeName $grantType): ?FlowPicture;
}
