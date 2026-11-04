<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Symfony\Component\Uid\Uuid;

interface IssuedInitialAccessTokensInterface
{
    /**
     * @return iterable<InitialAccessToken> the most recently issued first
     */
    public function issuedIn(Tenant $tenant): iterable;

    public function find(Tenant $tenant, Uuid $id): ?InitialAccessToken;
}
