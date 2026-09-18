<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * The shape of the access tokens a client receives (architecture §4.6): a JWT of RFC 9068 verified
 * offline, or an opaque reference presented to the introspection endpoint (RFC 7662). The registration
 * of the client chooses, nothing global.
 */
enum AccessTokenFormat: string
{
    case Jwt = 'jwt';
    case Opaque = 'opaque';
}
