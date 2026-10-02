<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use SensitiveParameter;

/**
 * Where the opaque access tokens live (architecture §4.6): the store keeps the record under the digest of
 * the value, and never the value. The value is drawn where every value this provider hands out is drawn
 * (SecretDrawer), so a store is a store here as everywhere else. What else it can do is declared by the
 * CanRevoke* companion interfaces.
 */
interface AccessTokenRepositoryInterface
{
    public function save(StoredAccessToken $token): void;

    public function find(#[SensitiveParameter] string $token): ?StoredAccessToken;
}
