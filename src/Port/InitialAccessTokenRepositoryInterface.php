<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;

/**
 * Where the initial access tokens of a tenant are kept (RFC 7591 §1.2). A token is looked up by the
 * digest of the value presented and never by the value, which the store never holds.
 */
interface InitialAccessTokenRepositoryInterface
{
    /**
     * @param string $digest see DrawnSecret::digestOf()
     *
     * @return InitialAccessToken|null null when that tenant has no token of that digest, which is what a
     *                                 value nobody was ever handed looks like
     */
    public function findByDigest(Tenant $tenant, string $digest): ?InitialAccessToken;

    /**
     * One of what the token is worth, claimed atomically: two requests presenting a token worth one
     * register one client between them, and the loser is refused as whoever presents a spent token is.
     * The token is left as the store holds it, so that the caller's copy says what the winner wrote.
     *
     * @return bool true when this call spent one, false when the token was spent, expired or revoked
     */
    public function spend(InitialAccessToken $token, DateTimeImmutable $now): bool;

    public function save(InitialAccessToken $token): void;
}
