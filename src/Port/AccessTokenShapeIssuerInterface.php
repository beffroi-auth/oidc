<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

interface AccessTokenShapeIssuerInterface extends AccessTokenIssuerInterface, AccessTokenShapeInterface
{
}
