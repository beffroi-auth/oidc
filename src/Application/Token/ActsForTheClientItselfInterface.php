<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * RFC 6749 §4.4
 */
interface ActsForTheClientItselfInterface extends RequiresClientAuthenticationInterface
{
}
