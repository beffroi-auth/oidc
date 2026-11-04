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
 * RFC 6749 §4.1.2, RFC 9700 §4.13.2
 */
final class RefreshTokenFamily implements ClassifiedFieldsInterface
{
    /**
     * @param Uuid $id not readonly: the persistence re-hydrates the identifier of an instance it already holds,
     *                 which PHP refuses on a readonly property
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
