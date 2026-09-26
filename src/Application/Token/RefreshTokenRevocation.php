<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Takes a set of refresh tokens out of use at once, for the reasons the protocol and the provider name: a
 * code presented twice (RFC 6749 §4.1.2), a rotated token presented again (RFC 9700 §4.13.2), a session
 * that ends (architecture §4.9), a consent taken back (architecture §4.3). A token already revoked keeps
 * its date and is not counted; what the caller announces, and which access tokens go with them, is the
 * caller's.
 *
 * The first three name their set by a question this store answers; the last is a set its caller holds,
 * found by a companion of the store (RefreshTokensOfAConsentInterface), and revoking it is this class all
 * the same, there being one place where a refresh token is taken out of use.
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
