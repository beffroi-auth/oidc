<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use DateTimeImmutable;
use function hash_equals;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Metadata\AssignedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * What the provider keeps of a client it registered itself (RFC 7591 §3.2.1): the tenant it belongs to,
 * the identifier the provider drew for it, the metadata as the client registered it, the secret the
 * provider handed it in the shape the registered method verifies against, the token that client reads
 * and deletes itself with (RFC 7592 §2.3), and the two dates the registration response carries.
 *
 * The metadata is kept as it was registered, in the names of RFC 7591 §2, and is read back by the reader
 * a declaration goes through: a row is not a second spelling of a registration, and a member this
 * provider learns to read tomorrow is read from the rows that already carry it.
 *
 * What the registration policy of the tenant wrote on the registration is kept beside it and not among
 * it (decision 0017): it is not what the client asked for, and the two would otherwise be one column a
 * client could write half of. It is read back in front of the members the client sent, so that what a
 * policy granted at the registration is what the client is registered with until that policy writes the
 * registration again (RFC 7592 §2.2).
 *
 * Neither the secret nor the registration access token is among those members. RFC 7591 §2 has no member
 * for either, the provider assigns both (§3.2.1), and each is kept apart so that the day they are
 * encrypted at rest is the day two columns change. The token is kept as its digest and never as its
 * value, like every value this provider draws.
 *
 * A replacement (RFC 7592 §2.2) is the same client under the same identifier: the row changes, and what
 * the provider assigned to it stays, the identifier, the date it was drawn on and the token it is read
 * with. An update is whole and never a patch, which is why what changes is given all at once. The date of
 * the last use is not part of a registration either: replacing one is not using the client.
 */
final class ClientRecord
{
    /**
     * When somebody last used this client (decision 0009): an authorization granted for it, a request it
     * made at the token endpoint. Null for a client that has never been used, which is not the same as one
     * used long ago and is not kept for as long.
     */
    public private(set) ?DateTimeImmutable $lastUsedAt = null;

    /**
     * @param array<string, mixed> $metadata the members of RFC 7591 §2 the client registered, as it registered them
     * @param array<string, mixed> $assigned the members the registration policy of the tenant wrote on this registration (decision 0017); empty for a policy that writes none
     * @param ClientSecretInterface|null $secret in the shape the registered method verifies against; null for a client whose method proves none
     * @param string $registrationAccessTokenDigest see DrawnSecret::digestOf(); the credential of this one client for its own configuration endpoint (RFC 7592 §2.3)
     * @param DateTimeImmutable|null $secretExpiresAt when the secret stops being verified (RFC 7591 §3.2.1 "client_secret_expires_at"); null for one that does not expire, which the response writes as 0
     *
     * @throws InvalidArgumentException when the record does not hold together
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
     * Somebody used this client at that instant. **The date only moves forward**: the two events that say
     * so are written to a queue and read from it, so they arrive in whatever order the queue gives them,
     * and a use recorded late must not make a client look older than it is.
     */
    public function recordUse(DateTimeImmutable $at): void
    {
        if ($this->lastUsedAt === null || $at > $this->lastUsedAt) {
            $this->lastUsedAt = $at;
        }
    }

    /**
     * The registration this row keeps, in the order the one reader of a registration reads it: what the
     * policy of the tenant wrote in front of what the client sent, behind the defaults of RFC 7591 §2.
     * The order is the row's own business, so it is named here and not again at each caller.
     */
    public function asRegistered(): ClientMetadata
    {
        return new ClientMetadata([
            new AssignedMembers($this->assigned),
            new RegisteredMembers($this->metadata),
            new SpecifiedDefaults(),
        ]);
    }

    /**
     * Whether this is the client that token reads and deletes itself with (RFC 7592 §2.3), compared in
     * constant time as every secret of this provider is. A token drawn for another client is a token
     * this one does not hold, which is the same answer as a token nobody was ever handed.
     *
     * @param string $digest see DrawnSecret::digestOf()
     */
    public function isReadWith(string $digest): bool
    {
        return hash_equals($this->registrationAccessTokenDigest, $digest);
    }

    /**
     * The registration this client replaced its own with (RFC 7592 §2.2): whole, never a patch, so a
     * member it left out is a member it no longer registers. What the provider assigned does not change.
     *
     * @param array<string, mixed> $metadata
     * @param array<string, mixed> $assigned
     *
     * @throws InvalidArgumentException when what is left does not hold together
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
}
