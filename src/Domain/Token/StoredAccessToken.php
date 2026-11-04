<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token as the provider keeps it.
 */
abstract readonly class StoredAccessToken implements HashedTokenInterface, ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public Tenant $tenant;

    public string $clientId;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $tokenHash,
        public Uuid $grantId,
        public Client $client,
        public Scopes $scopes,
        public ?ResourceIndicators $resources,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
    ) {
        if (! DrawnSecret::isDigest($tokenHash)) {
            throw new InvalidArgumentException('An opaque access token is stored as its hex SHA-256.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * The person the token was issued for, by the subject their account carries; null when it names nobody.
     */
    abstract public function person(): ?Subject;

    /**
     * Null when the record keeps its person itself or names nobody, which person() then answers. An identifier, so
     * that the person is read without opening the session (decision 0011).
     */
    abstract public function sessionNamingItsPerson(): ?Uuid;

    public function clientHolder(): object
    {
        return $this;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'confirmation' => new NoPersonalDatum(Reason::WHAT_A_TOKEN_IS_BOUND_TO),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'tokenHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
