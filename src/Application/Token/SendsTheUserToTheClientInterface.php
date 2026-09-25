<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

/**
 * A grant whose flow sends the user's browser back to the client (RFC 6749 §3.1.2): the authorization it
 * spends was obtained at a redirect URI, so a client registered for it registers at least one.
 *
 * A grant that continues such a flow without a browser of its own, as the refresh of a token does, declares
 * nothing here: it is the grant that got the authorization which needed the redirect URI, and a client
 * registered for the second is registered for the first.
 */
interface SendsTheUserToTheClientInterface extends GrantInterface
{
}
