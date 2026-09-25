<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AuthorizationInterface;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use SensitiveParameter;

/**
 * Where the opaque access tokens live (architecture §4.6): the store draws the value and keeps the hash.
 * What else it can do is declared by the CanRevoke* companion interfaces.
 */
interface AccessTokenRepositoryInterface
{
    /**
     * The record of the kind the authorization is, written under the digest of the value drawn for it.
     *
     * @return string the value, for the response and nothing else
     */
    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): string;

    public function find(#[SensitiveParameter] string $token): ?StoredAccessToken;
}
