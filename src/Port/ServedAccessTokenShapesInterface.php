<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

interface ServedAccessTokenShapesInterface
{
    /**
     * @return non-empty-list<AccessTokenShapeInterface> the first is the shape a client that registers none takes
     */
    public function servedAccessTokenShapes(): array;
}
