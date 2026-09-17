<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * The shape of the access tokens a client receives (architecture §4.6). Self-contained: a signed JWT of
 * RFC 9068, verified offline against the JWK Set, which no round trip and no revocation reach. Opaque: a
 * random reference the provider keeps, which a resource server presents to the introspection endpoint
 * (RFC 7662) and which a logout, a replayed code or the revocation endpoint (RFC 7009) kill at once.
 * Neither is the less secure one, so neither is the rule: the registration of the client chooses, and
 * nothing global turns a whole tenant one way.
 */
enum AccessTokenFormat: string
{
    case Jwt = 'jwt';
    case Opaque = 'opaque';
}
