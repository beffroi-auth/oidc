<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Record\ExpiringRecord;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function hash_equals;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2
 */
final class InitialAccessToken extends ExpiringRecord implements ClassifiedFieldsInterface
{
    public private(set) int $registrationsServed = 0;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        public readonly Uuid $id,
        public readonly Tenant $tenant,
        public readonly string $digest,
        public readonly string $name,
        public readonly int $registrationsAllowed,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?GrantedMembers $granted = null,
        public readonly bool $administration = false,
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
     * Compared in constant time, even after a store found the token by that digest.
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

    public function authorisesARegistration(DateTimeImmutable $now): bool
    {
        return ! $this->isSpent() && ! $this->isRevoked() && ! $this->isExpired($now);
    }

    /**
     * On this copy only: the store's claim is what spends it once when two requests present it together.
     */
    public function spend(): void
    {
        $this->registrationsServed++;
    }

    public function recordRegistrationsServed(int $registrationsServed): void
    {
        $this->registrationsServed = $registrationsServed;
    }

    public function revoke(DateTimeImmutable $now): void
    {
        $this->revokedAt ??= $now;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'digest' => new NoPersonalDatum(Reason::HASHED),
            'name' => new NoPersonalDatum('the name an operator gave a token, so that one can be told from another'),
            'registrationsAllowed' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'registrationsServed' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'revokedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'granted' =>
                new NoPersonalDatum('what the token gives the clients it registers: identifiers of APIs, the shape and binding of their access tokens, the types of token they may exchange, and the subject that may act for the subject of their tokens, a pseudonym every token carries in the clear'),
            'administration' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
