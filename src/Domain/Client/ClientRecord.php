<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use DateTimeImmutable;
use function hash_equals;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Metadata\AssignedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * A client that registered itself (RFC 7591 §3.2.1), as the provider stores it.
 */
final class ClientRecord implements ClassifiedFieldsInterface
{
    public private(set) ?DateTimeImmutable $lastUsedAt = null;

    /**
     * @param array<string, mixed> $metadata the RFC 7591 §2 members, as the client registered them
     * @param array<string, mixed> $assigned the members the tenant's registration policy wrote
     * @param array<string, mixed>|null $attested what a software statement signed, which no replacement overwrites
     * @param array<string, mixed>|null $granted what the initial access token that registered it gave, which no replacement overwrites
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public readonly Uuid $id,
        public readonly Tenant $tenant,
        public readonly string $clientId,
        public private(set) array $metadata,
        public private(set) array $assigned,
        #[SensitiveParameter]
        public private(set) ?ClientSecretInterface $secret,
        public readonly string $registrationAccessTokenDigest,
        public readonly DateTimeImmutable $issuedAt,
        public private(set) ?DateTimeImmutable $secretExpiresAt = null,
        public readonly ?array $attested = null,
        public readonly ?array $granted = null,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('A registered client carries the identifier the provider drew for it (RFC 7591 section 3.2.1).');
        }
        if (! DrawnSecret::isDigest($registrationAccessTokenDigest)) {
            throw new InvalidArgumentException(sprintf(
                'The registration access token of the client "%s" is stored as the hex SHA-256 of its value, never as the value.',
                $clientId,
            ));
        }
        $this->assertTheSecretHoldsTogether();
    }

    public function belongsTo(Tenant $tenant): bool
    {
        return $this->tenant->equals($tenant);
    }

    /**
     * The date only moves forward: uses are read from a queue, in whatever order it gives them.
     */
    public function recordUse(DateTimeImmutable $at): void
    {
        if ($this->lastUsedAt === null || $at > $this->lastUsedAt) {
            $this->lastUsedAt = $at;
        }
    }

    /**
     * @throws InvalidClientMetadataException
     */
    public function asRegistered(): ClientMetadata
    {
        $grants = $this->grants();

        return new ClientMetadata([
            ...($grants === null ? [] : [$grants]),
            new AssignedMembers($this->assigned),
            new RegisteredMembers($this->metadata),
            new SpecifiedDefaults(),
        ]);
    }

    /**
     * @throws InvalidClientMetadataException
     */
    public function grants(): ?GrantedMembers
    {
        return $this->granted === null ? null : new GrantedMembers($this->granted);
    }

    /**
     * @throws InvalidClientMetadataException
     *
     * @return list<ClientMetadataSourceInterface>
     */
    public function attestation(): array
    {
        return $this->attested === null ? [] : [new AttestedMembers($this->attested)];
    }

    /**
     * Compared in constant time.
     */
    public function isReadWith(string $digest): bool
    {
        return hash_equals($this->registrationAccessTokenDigest, $digest);
    }

    /**
     * RFC 7592 §2.2
     *
     * @param array<string, mixed> $metadata
     * @param array<string, mixed> $assigned
     *
     * @throws InvalidArgumentException
     */
    public function replaceWith(
        array $metadata,
        array $assigned,
        #[SensitiveParameter]
        ?ClientSecretInterface $secret,
        ?DateTimeImmutable $secretExpiresAt = null,
    ): void {
        $this->metadata = $metadata;
        $this->assigned = $assigned;
        $this->secret = $secret;
        $this->secretExpiresAt = $secretExpiresAt;
        $this->assertTheSecretHoldsTogether();
    }

    /**
     * @throws InvalidArgumentException
     */
    private function assertTheSecretHoldsTogether(): void
    {
        if ($this->secret === null && $this->secretExpiresAt !== null) {
            throw new InvalidArgumentException(sprintf('The client "%s" holds no secret, so nothing of it expires.', $this->clientId));
        }
        if ($this->secretExpiresAt !== null && $this->secretExpiresAt <= $this->issuedAt) {
            throw new InvalidArgumentException(sprintf('The secret of the client "%s" expires after it was issued.', $this->clientId));
        }
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'metadata' => new Sealed('client'),
            'assigned' => new Sealed('client'),
            'attested' => new Sealed('client'),
            'granted' => new Sealed('client'),
            'registrationAccessTokenDigest' => new NoPersonalDatum(Reason::HASHED),
            'secret' => new Sealed('client'),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'lastUsedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'secretExpiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
