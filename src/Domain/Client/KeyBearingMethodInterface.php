<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * A method that verifies a signature made by a key of the client (OIDC Core §9): the client publishes a
 * JWK Set, inline or behind a "jwks_uri" (RFC 7591 §2), and a registration that publishes neither is a
 * registration that cannot work, refused when it is read. It carries nothing else: what the client has
 * to publish is the whole of the rule.
 */
interface KeyBearingMethodInterface extends ClientAuthenticationMethodInterface
{
}
