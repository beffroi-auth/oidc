<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

final readonly class RefreshTokenRevocation
{
    public function __construct(
        private RefreshTokenRepositoryInterface $refreshTokens,
    ) {
    }

    /**
     * @param string $codeHash see DrawnSecret::digestOf()
     *
     * @return list<RefreshToken> the tokens revoked by this call
     */
    public function revokeByAuthorizationCode(string $codeHash, DateTimeImmutable $now): array
    {
        return $this->revokeAll($this->refreshTokens->findByAuthorizationCode($codeHash), $now);
    }

    /**
     * @return list<RefreshToken> the tokens revoked by this call
     */
    public function revokeFamily(Uuid $family, DateTimeImmutable $now): array
    {
        return $this->revokeAll($this->refreshTokens->findByFamily($family), $now);
    }

    /**
     * @return list<RefreshToken> the tokens revoked by this call
     */
    public function revokeBySession(Uuid $session, DateTimeImmutable $now): array
    {
        return $this->revokeAll($this->refreshTokens->findBySession($session), $now);
    }

    /**
     * @param iterable<RefreshToken> $tokens
     *
     * @return list<RefreshToken> the tokens revoked by this call
     */
    public function revokeAll(iterable $tokens, DateTimeImmutable $now): array
    {
        $revoked = [];
        foreach ($tokens as $token) {
            if ($token->isRevoked()) {
                continue;
            }
            $token->revoke($now);
            $this->refreshTokens->save($token);
            $revoked[] = $token;
        }

        return $revoked;
    }
}
