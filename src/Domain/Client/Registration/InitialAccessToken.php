<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Record\ExpiringRecord;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function hash_equals;
use Symfony\Component\Uid\Uuid;

/**
 * What a tenant hands to whoever may register a client for it (RFC 7591 §1.2, decision 0009): a value
 * drawn like every other value this provider hands out and recognises again, kept as its digest and
 * never as its value, worth a number of registrations and no more, expiring, and revocable.
 *
 * It is not an access token of the provider: it opens no endpoint, carries no subject and no scope, and
 * says one thing only, that the caller presenting it may register a client with this tenant. The tenant
 * names it so that whoever issued it can say later which integration it was for.
 *
 * What it is worth is spent in the same request as the registration it authorises: a token worth one
 * client registers one, whether the registration that followed it was written or refused on its
 * metadata. Refusing it is one refusal whatever gave it away, unknown, spent, expired or revoked: a
 * caller learns nothing about a token it does not hold (decision 0006).
 */
final class InitialAccessToken extends ExpiringRecord
{
    public private(set) int $registrationsServed = 0;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param string $digest see DrawnSecret::digestOf()
     * @param string $name what the tenant calls this token, for whoever issued it to know which integration it was for; never empty
     * @param int $registrationsAllowed how many clients it may register; at least one
     *
     * @throws InvalidArgumentException when the token does not hold together
     */
    public function __construct(
        public readonly Uuid $id,
        public readonly Tenant $tenant,
        public readonly string $digest,
        public readonly string $name,
        public readonly int $registrationsAllowed,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (! DrawnSecret::isDigest($digest)) {
            throw new InvalidArgumentException('An initial access token is stored as the hex SHA-256 of its value, never as the value.');
        }
        if ($name === '') {
            throw new InvalidArgumentException('An initial access token carries the name the tenant gave it (RFC 7591 section 1.2).');
        }
        if ($registrationsAllowed < 1) {
            throw new InvalidArgumentException('An initial access token is worth at least one registration; a token worth none is a token not issued.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An initial access token expires after it was issued.');
        }
    }

    public function belongsTo(Tenant $tenant): bool
    {
        return $this->tenant->equals($tenant);
    }

    /**
     * Whether this is the token that value names, compared in constant time as every secret of this
     * provider is: the store answered by the digest, and this is what says the answer is the question.
     *
     * @param string $digest see DrawnSecret::digestOf()
     */
    public function matches(string $digest): bool
    {
        return hash_equals($this->digest, $digest);
    }

    public function isSpent(): bool
    {
        return $this->registrationsServed >= $this->registrationsAllowed;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /**
     * Whether this token still authorises a registration at that instant, which is what the caller reads
     * before spending it; the store is what makes the spending atomic.
     */
    public function authorisesARegistration(DateTimeImmutable $now): bool
    {
        return ! $this->isSpent() && ! $this->isRevoked() && ! $this->isExpired($now);
    }

    /**
     * One registration of what the token is worth, on the copy the caller holds; what makes it happen
     * once when two requests present it together is the store that claims it.
     */
    public function spend(): void
    {
        $this->registrationsServed++;
    }

    /**
     * For a store whose claim was lost, or that read the count back: what the store holds.
     */
    public function recordRegistrationsServed(int $registrationsServed): void
    {
        $this->registrationsServed = $registrationsServed;
    }

    /**
     * A token the tenant took back: it authorises nothing from that instant, whatever it was still worth.
     */
    public function revoke(DateTimeImmutable $now): void
    {
        $this->revokedAt ??= $now;
    }
}
