<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Takes a set of refresh tokens out of use at once, for the three reasons the protocol names: a code
 * presented twice (RFC 6749 §4.1.2), a rotated token presented again (RFC 9700 §4.13.2), a session that
 * ends (architecture §4.9). A token already revoked keeps its date and is not counted; what the caller
 * announces, and which access tokens go with them, is the caller's.
 */
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
     * @return list<RefreshToken>
     */
    private function revokeAll(iterable $tokens, DateTimeImmutable $now): array
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
