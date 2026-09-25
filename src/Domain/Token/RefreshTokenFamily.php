<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * The lineage of refresh tokens descending from one record the provider read once (architecture §4.6): an
 * authorization code (RFC 6749 §4.1.3) or a device authorization request (RFC 8628 §3.4). The whole
 * lineage is revoked at once on a reuse or a replay (RFC 6749 §4.1.2, RFC 9700 §4.13.2), and it carries
 * the absolute lifetime no rotation extends.
 */
final readonly class RefreshTokenFamily
{
    /**
     * @param string $grantingRecordHash the hex SHA-256 of the record this family descends from, an
     *                                   authorization code or a device code
     */
    public function __construct(
        public Uuid $id,
        public string $grantingRecordHash,
        public Uuid $grantId,
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if (! DrawnSecret::isDigest($grantingRecordHash)) {
            throw new InvalidArgumentException('A refresh token family descends from a record read once, named by its hex SHA-256.');
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
