<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §8.1
 *
 * Kept for the way back: the value is a one-way hash, and only this row tells whom a presented "sub" names.
 */
final class PairwiseSubject implements ClassifiedFieldsInterface
{
    public readonly Tenant $tenant;

    /**
     * On every entity the identifier is private(set), not readonly: a mapper building lazy references
     * assigns it twice.
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly SectorIdentifier $sector,
        public readonly Subject $subject,
        public readonly DateTimeImmutable $assignedAt,
    ) {
        $this->tenant = $user->tenant;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'sector' => new NoPersonalDatum('the sector a client registered, a host or the URL of a document, not a person'),
            'subject' => new NoPersonalDatum(Reason::THE_SUBJECT),
            'assignedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'user' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
