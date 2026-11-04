<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;

interface AuthorizationDetailsReaderInterface
{
    /**
     * RFC 9396 §2
     *
     * @throws InvalidArgumentException
     */
    public function fromJson(string $json): AuthorizationDetails;

    /**
     * RFC 9396 §7, §9
     *
     * @throws InvalidArgumentException
     */
    public function fromClaim(mixed $claim): AuthorizationDetails;
}
