<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

interface AccessTokenShapeInterface
{
    /**
     * @return non-empty-string
     */
    public function name(): string;
}
