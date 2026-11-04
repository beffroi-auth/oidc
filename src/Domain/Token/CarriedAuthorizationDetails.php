<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;

/**
 * RFC 9396 §2, §7
 */
final readonly class CarriedAuthorizationDetails
{
    public static function of(AuthorizationInterface $authorization): ?AuthorizationDetails
    {
        return $authorization instanceof UserAuthorizationInterface ? $authorization->authorizationDetails : null;
    }
}
