<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * A grant a client uses for itself, with nobody signed in behind it (RFC 6749 §4.4): it authenticates the
 * client and nothing else, so it is served only to a client that authenticates itself, and it sends no
 * browser anywhere, so a client that only uses grants of this kind registers no redirect URI.
 *
 * A grant declares this instead of anything reading its name: what a registration of such a grant must
 * carry and must not carry is decided where a registration meets the wiring, from this.
 */
interface ActsForTheClientItselfInterface extends RequiresClientAuthenticationInterface
{
}
