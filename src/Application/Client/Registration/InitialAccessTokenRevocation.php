<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

final readonly class InitialAccessTokenRevocation
{
    public function __construct(
        private IssuedInitialAccessTokensInterface $issued,
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    public function revoke(Tenant $tenant, Uuid $id): ?InitialAccessToken
    {
        $token = $this->issued->find($tenant, $id);
        if ($token === null) {
            return null;
        }
        $token->revoke($this->clock->now());
        $this->tokens->save($token);

        return $token;
    }
}
