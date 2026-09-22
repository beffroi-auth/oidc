<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\PushedAuthorization;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function max;
use function preg_match;

/**
 * An authorization request a client pushed before sending its user (RFC 9126 §2), as the provider keeps
 * it: the SHA-256 of the reference it answered with, the client it is bound to (§2.2), and the
 * parameters the authorization endpoint will read in place of the query (§4). The parameters are kept
 * as the client wrote them and not as the parser understood them, so that the endpoint reads one request
 * whichever way it arrived; what authenticated the client at the endpoint is not among them.
 *
 * The record is read once: the repository claims it atomically and the winner consumes it, as it does an
 * authorization code. A consumed or expired record grants nothing and stays only so that the next
 * presentation is told from a reference nobody ever issued.
 */
final class PushedAuthorizationRequest
{
    public const string HASH_PATTERN = '/^[0-9a-f]{64}$/';

    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $usedAt = null;

    /**
     * @param string $requestUriHash see RequestUri::hashOf()
     * @param array<string, string> $parameters the form parameters the client pushed, credentials taken out
     * @param bool $carriedBySignedObject whether the push carried a request object the client signed
     *                                    (RFC 9101 §6.1), which the authorization endpoint can no longer
     *                                    see once the record answers for the request
     */
    public function __construct(
        public readonly string $requestUriHash,
        public readonly Client $client,
        public readonly array $parameters,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly bool $carriedBySignedObject = false,
    ) {
        if (preg_match(self::HASH_PATTERN, $requestUriHash) !== 1) {
            throw new InvalidArgumentException('A pushed authorization request is stored as the hex SHA-256 of its request URI.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A pushed authorization request expires after it was pushed.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->clientId;
    }

    /**
     * RFC 9126 §2.2: a positive number of seconds, rounded up so that the client is never told a
     * lifetime longer than the one the record has.
     *
     * @return positive-int
     */
    public function expiresIn(DateTimeImmutable $now): int
    {
        return max(1, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }

    /**
     * RFC 9126 §4: one use. The repository claims the record atomically and calls this on the winner;
     * called twice is a programming error, not a replay.
     */
    public function consume(DateTimeImmutable $now): void
    {
        if ($this->usedAt !== null) {
            throw new LogicException('A pushed authorization request is consumed once; the authorization endpoint checks isUsed() first.');
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

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    public function belongsTo(Client $client): bool
    {
        return $this->clientId === $client->clientId && $this->tenant->equals($client->tenant);
    }
}
