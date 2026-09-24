<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * The lineage of refresh tokens descending from one authorization code (architecture §4.6), revoked at
 * once on a reuse or a replay (RFC 6749 §4.1.2, RFC 9700 §4.13.2). It carries the absolute lifetime no
 * rotation extends.
 */
final readonly class RefreshTokenFamily
{
    public function __construct(
        public Uuid $id,
        public string $authorizationCodeHash,
        public Uuid $grantId,
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if (! DrawnSecret::isDigest($authorizationCodeHash)) {
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
