<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Grant;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Record\RecordReadOnce;
use Symfony\Component\Uid\Uuid;

abstract class GrantRecord extends RecordReadOnce
{
    abstract public Uuid $grantId { get; }

    public private(set) ?DateTimeImmutable $revokedAt = null;

    public function revoke(DateTimeImmutable $now): void
    {
        $this->revokedAt ??= $now;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'revokedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
