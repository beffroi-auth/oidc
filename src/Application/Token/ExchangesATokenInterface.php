<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * RFC 8693 §2.1
 */
interface ExchangesATokenInterface extends RequiresClientAuthenticationInterface
{
}
