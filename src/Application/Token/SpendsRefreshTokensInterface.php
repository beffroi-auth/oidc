<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * A grant that spends a refresh token (RFC 6749 §6): it issues nothing that was not obtained first, so
 * it is worth something only beside a grant that issues one, and a client registered for it is
 * registered for one of those too.
 */
interface SpendsRefreshTokensInterface extends GrantInterface
{
}
