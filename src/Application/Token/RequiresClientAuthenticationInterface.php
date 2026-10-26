<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * A grant served only to a client that authenticates itself: nobody signs in at this provider for what it
 * issues, so the client is the one party the response stands on, and a public client, which cannot
 * authenticate (RFC 6749 §2.1), is never served it. A client acting for itself is one such grant (RFC 6749
 * §4.4); so is one that presents something naming somebody this provider did not sign in, a token it issued
 * (RFC 8693 §2.1) or the assertion of an issuer the tenant trusts (RFC 7523 §2.1). Those two specifications
 * leave client authentication to the server, and RFC 8693 §2.1 says what doing without it costs: whoever
 * holds a token that leaked turns it into other tokens.
 *
 * A grant declares this instead of anything reading its name: a registration of such a grant with a method
 * that authenticates nobody is refused where a registration meets the wiring, and a request of a public
 * client for it is refused at the token endpoint before the grant reads anything, both from this.
 */
interface RequiresClientAuthenticationInterface extends GrantInterface
{
}
