<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * RFC 8693 §2.1 and RFC 7523 §2.1 leave client authentication optional; it is required, as whoever holds a leaked
 * token would turn it into other tokens.
 */
interface RequiresClientAuthenticationInterface extends GrantInterface
{
}
