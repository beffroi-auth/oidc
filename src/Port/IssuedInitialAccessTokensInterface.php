<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * The initial access tokens a tenant has issued, as whoever issued them looks at them (RFC 7591 §1.2,
 * decision 0009): which ones exist, what each has served and what it has left.
 *
 * It is not the port the registration endpoint reads. That one is handed a value and asks the store
 * whether it names a token, by a digest and never by an identifier, and it may see one token at a time
 * and no other (`InitialAccessTokenRepositoryInterface`). This one is handed a tenant and never a value,
 * and sees every token and no digest to present. The two callers are disjoint, so the ports are.
 */
interface IssuedInitialAccessTokensInterface
{
    /**
     * @return iterable<InitialAccessToken> the tokens of that tenant, the most recently issued first
     */
    public function issuedIn(Tenant $tenant): iterable;

    /**
     * @return InitialAccessToken|null null when that tenant has no token of that identifier, which is
     *                                 what a token of another tenant looks like from here
     */
    public function find(Tenant $tenant, Uuid $id): ?InitialAccessToken;
}
