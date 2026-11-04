<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Record;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Oidc\Exception\LogicException;
use function sprintf;

/**
 * A used record is kept, so that a second presentation is told from a reference nobody ever issued.
 */
abstract class RecordReadOnce extends ExpiringRecord implements ClassifiedFieldsInterface
{
    public private(set) ?DateTimeImmutable $usedAt = null;

    /**
     * @throws LogicException
     */
    public function consume(DateTimeImmutable $now): void
    {
        if ($this->usedAt !== null) {
            throw new LogicException(sprintf('%s is consumed once; %s checks isUsed() first.', $this->nameOfRecord(), $this->readerThatChecks()));
        }
        $this->usedAt = $now;
    }

    /**
     * For a repository whose claim was lost: the instant the store holds.
     */
    public function recordConsumption(DateTimeImmutable $usedAt): void
    {
        $this->usedAt = $usedAt;
    }

    public function isUsed(): bool
    {
        return $this->usedAt !== null;
    }

    /**
     * How the record names itself in a refusal, article included: "An authorization code".
     */
    abstract protected function nameOfRecord(): string;

    /**
     * Who reads isUsed() before consuming, article included: "the grant".
     */
    abstract protected function readerThatChecks(): string;

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'usedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
