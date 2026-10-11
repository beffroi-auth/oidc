<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * The lineage of refresh tokens descending from one record the provider read once (architecture §4.6): an
 * authorization code (RFC 6749 §4.1.3) or a device authorization request (RFC 8628 §3.4). The whole
 * lineage is revoked at once on a reuse or a replay (RFC 6749 §4.1.2, RFC 9700 §4.13.2), and it carries
 * the absolute lifetime no rotation extends.
 */
final class RefreshTokenFamily implements ClassifiedFieldsInterface
{
    /**
     * @param Uuid $id not readonly, and the one property of this class that is not: a row every token of
     *                 the lineage names is the target of an association, and the persistence re-hydrates
     *                 the identifier of an instance it already holds, which PHP refuses on a readonly
     *                 property. The three entities of this model that are readonly whole are the three
     *                 nothing points at.
     * @param string $grantingRecordHash the hex SHA-256 of the record this family descends from, an
     *                                   authorization code or a device code
     */
    public function __construct(
        public Uuid $id,
        public readonly Tenant $tenant,
        public readonly string $grantingRecordHash,
        public readonly Uuid $grantId,
        public readonly DateTimeImmutable $startedAt,
        public readonly DateTimeImmutable $expiresAt,
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

    /**
     * A lineage of refresh tokens: the record it was granted on as a digest, and the two instants that bound it.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'grantingRecordHash' => new NoPersonalDatum(Reason::HASHED),
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'startedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
