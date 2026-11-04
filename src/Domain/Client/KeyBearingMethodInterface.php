<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * A method verifying a signature by the client's key, so that its registration must publish keys (OIDC Core §9).
 */
interface KeyBearingMethodInterface extends ClientAuthenticationMethodInterface
{
}
