<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

/**
 * What the provider keeps of a client it registered itself (RFC 7591 §3.2.1): the tenant it belongs to,
 * the identifier the provider drew for it, the metadata as the client registered it, the secret the
 * provider handed it in the shape the registered method verifies against, and the two dates the
 * registration response carries.
 *
 * The metadata is kept as it was registered, in the names of RFC 7591 §2, and is read back by the reader
 * a declaration goes through: a row is not a second spelling of a registration, and a member this
 * provider learns to read tomorrow is read from the rows that already carry it.
 *
 * The secret is not among those members. RFC 7591 §2 has none for it, the provider assigns it (§3.2.1),
 * and it is kept apart so that the day it is encrypted at rest is the day one column changes.
 */
final readonly class ClientRecord
{
    /**
     * @param array<string, mixed> $metadata the members of RFC 7591 §2 the client registered, as it registered them
     * @param ClientSecretInterface|null $secret in the shape the registered method verifies against; null for a client whose method proves none
     * @param DateTimeImmutable|null $secretExpiresAt when the secret stops being verified (RFC 7591 §3.2.1 "client_secret_expires_at"); null for one that does not expire, which the response writes as 0
     *
     * @throws InvalidArgumentException when the record does not hold together
     */
    public function __construct(
        public Uuid $id,
        public Tenant $tenant,
        public string $clientId,
        public array $metadata,
        #[SensitiveParameter]
        public ?ClientSecretInterface $secret,
        public DateTimeImmutable $issuedAt,
        public ?DateTimeImmutable $secretExpiresAt = null,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('A registered client carries the identifier the provider drew for it (RFC 7591 section 3.2.1).');
        }
        if ($secret === null && $secretExpiresAt !== null) {
            throw new InvalidArgumentException(sprintf('The client "%s" holds no secret, so nothing of it expires.', $clientId));
        }
        if ($secretExpiresAt !== null && $secretExpiresAt <= $issuedAt) {
            throw new InvalidArgumentException(sprintf('The secret of the client "%s" expires after it was issued.', $clientId));
        }
    }

    public function belongsTo(Tenant $tenant): bool
    {
        return $this->tenant->equals($tenant);
    }
}
