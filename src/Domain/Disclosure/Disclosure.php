<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Disclosure;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * What a client was given of a person at one act of the protocol. Its identifier is a UUIDv7, so that a person's
 * register sorts by its primary key.
 */
final class Disclosure implements ClassifiedFieldsInterface
{
    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly Tenant $tenant,
        public readonly Subject $subject,
        public readonly string $clientId,
        public readonly string $act,
        public readonly DateTimeImmutable $handedOverAt,
        public readonly Scopes $scopes,
        public readonly ?ClaimsRequest $claims,
        public readonly ?AuthorizationDetails $details,
        public readonly string $tokenShape,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('What a client was given names the client.');
        }
        if ($act === '') {
            throw new InvalidArgumentException('What a client was given names the act it left with.');
        }
        if ($tokenShape === '') {
            throw new InvalidArgumentException('What a client was given names the shape the access token was written in.');
        }
    }

    /**
     * Sealed, unlike a consent: a dump of it would tell what an application obtained of somebody, day by day.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'subject' => new NoPersonalDatum(Reason::THE_SUBJECT),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'act' => new NoPersonalDatum('the name of the act it left with, which an event gives itself and which names no person'),
            'handedOverAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'scopes' => new Sealed('disclosure'),
            'claims' => new Sealed('disclosure'),
            'details' => new Sealed('disclosure'),
            'tokenShape' => new NoPersonalDatum('the shape the access token was written in, which names no person'),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
