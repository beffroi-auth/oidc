<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;

/**
 * The store holds the digest of a token's value and never the value.
 */
interface InitialAccessTokenRepositoryInterface
{
    /**
     * @param string $digest see DrawnSecret::digestOf()
     */
    public function findByDigest(Tenant $tenant, string $digest): ?InitialAccessToken;

    /**
     * Claims one of the uses of the token atomically, and leaves the caller's copy as the store holds it.
     *
     * @return bool false when the token was spent, expired or revoked
     */
    public function spend(InitialAccessToken $token, DateTimeImmutable $now): bool;

    public function save(InitialAccessToken $token): void;
}
