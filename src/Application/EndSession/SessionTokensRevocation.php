<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use DateTimeImmutable;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;

final readonly class SessionTokensRevocation
{
    public function __construct(
        private RefreshTokenRevocation $refreshTokens,
        private CanRevokeAccessTokensBySessionInterface $accessTokens,
    ) {
    }

    public function sessionEnded(Uuid $session, DateTimeImmutable $endedAt): void
    {
        $this->refreshTokens->revokeBySession($session, $endedAt);
        $this->accessTokens->revokeBySession($session);
    }
}
