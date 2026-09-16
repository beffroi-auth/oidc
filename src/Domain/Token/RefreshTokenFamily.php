<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use Symfony\Component\Uid\Uuid;

/**
 * The lineage of refresh tokens that descends from one authorization code (architecture §4.4, §4.6):
 * every rotation issues a new token in the same family, so that the reuse of a rotated token, or the
 * replay of the code, revokes them all at once (RFC 6749 §4.1.2, RFC 9700 §4.13.2). The family carries
 * the absolute lifetime that no rotation extends; each token carries its own sliding one.
 */
final readonly class RefreshTokenFamily
{
    /**
     * @param string $authorizationCodeHash the hash of the code the first token was exchanged for
     * @param Uuid $grantId the grant of that code, carried here so that a refreshed access token names the same one
     * @param DateTimeImmutable $startedAt when the code was exchanged
     * @param DateTimeImmutable $expiresAt after which no token of the family is accepted, whatever its own expiry
     */
    public function __construct(
        public Uuid $id,
        public string $authorizationCodeHash,
        public Uuid $grantId,
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if (preg_match(AuthorizationCode::HASH_PATTERN, $authorizationCodeHash) !== 1) {
            throw new InvalidArgumentException('A refresh token family descends from an authorization code, named by its hex SHA-256.');
        }
        if ($expiresAt <= $startedAt) {
            throw new InvalidArgumentException('A refresh token family expires after it started.');
        }
    }

    public function equals(self $other): bool
    {
        return $this->id->equals($other->id);
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
