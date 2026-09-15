<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * Where issued authorization codes wait for the token endpoint. The lookup by hash and the marking of a
 * used code come with the authorization code grant (architecture §4.5).
 */
interface AuthorizationCodeRepositoryInterface
{
    public function save(AuthorizationCode $code): void;
}
