<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use SensitiveParameter;

/**
 * Opaque access tokens, kept under the digest of their value and never the value.
 */
interface AccessTokenRepositoryInterface
{
    public function save(StoredAccessToken $token): void;

    public function find(#[SensitiveParameter] string $token): ?StoredAccessToken;
}
