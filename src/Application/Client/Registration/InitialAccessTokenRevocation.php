<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenRevoked;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A token revoked already is answered as it is, and no act is written again.
 */
final readonly class InitialAccessTokenRevocation
{
    public function __construct(
        private IssuedInitialAccessTokensInterface $issued,
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    public function revoke(Tenant $tenant, Uuid $id, RequestContext $context): ?InitialAccessToken
    {
        return $this->revokeOnce($tenant, $id, $context, null);
    }

    /**
     * The act names the administrator (decision 0038).
     */
    public function revokeByAnAdministrator(Tenant $tenant, Uuid $id, Subject $administrator, RequestContext $context): ?InitialAccessToken
    {
        return $this->revokeOnce($tenant, $id, $context, $administrator);
    }

    private function revokeOnce(Tenant $tenant, Uuid $id, RequestContext $context, ?Subject $administrator): ?InitialAccessToken
    {
        $token = $this->issued->find($tenant, $id);
        if ($token === null || $token->isRevoked()) {
            return $token;
        }
        $now = $this->clock->now();
        $token->revoke($now);
        $this->tokens->save($token);
        $this->events->dispatch(new InitialAccessTokenRevoked($now, $tenant, $token->id, $context, $administrator));

        return $token;
    }
}
