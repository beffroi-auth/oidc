<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function base64_encode;
use DateTimeImmutable;
use function hash;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function preg_match;
use function random_bytes;
use function rtrim;
use SensitiveParameter;
use function strtr;
use Symfony\Component\Uid\Uuid;

/**
 * An authorization code (RFC 6749 §4.1.2, architecture §4.4) as the provider keeps it: the SHA-256 of the
 * value, and everything the token endpoint needs, what the session had proven, frozen in an
 * AuthenticationSnapshot at issuance. The record is also the grant the tokens descend from, named by "grantId".
 */
final class AuthorizationCode
{
    public const string HASH_PATTERN = '/^[0-9a-f]{64}$/';

    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $usedAt = null;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param string $codeHash see hash()
     * @param CodeChallenge|null $codeChallenge null only for a client that does not require PKCE (decision 0008)
     * @param KeyConfirmation|null $dpopKey the key the request reserved the code for (RFC 9449 §10), null when it reserved it for none
     * @param AuthenticationSnapshot $authentication what the session had proven, frozen for every token of the grant
     */
    public function __construct(
        public readonly string $codeHash,
        public readonly Uuid $grantId,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        public readonly RedirectUri $redirectUri,
        public readonly Scopes $scopes,
        public readonly ?string $nonce,
        public readonly ?CodeChallenge $codeChallenge,
        public readonly ?KeyConfirmation $dpopKey,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly AuthenticationSnapshot $authentication,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (preg_match(self::HASH_PATTERN, $codeHash) !== 1) {
            throw new InvalidArgumentException('An authorization code is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization code binds a session and a client of the same tenant.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An authorization code expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * 256 bits, base64url without padding.
     */
    public static function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function hash(#[SensitiveParameter] string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * RFC 6749 §4.1.2. The repository claims the record atomically and calls this on the winner; called
     * twice is a programming error, not a replay.
     */
    public function consume(DateTimeImmutable $now): void
    {
        if ($this->usedAt !== null) {
            throw new LogicException('An authorization code is consumed once; the grant checks isUsed() first.');
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
     * RFC 6749 §4.1.2: the replay of a code revokes what was issued from it.
     */
    public function revoke(DateTimeImmutable $now): void
    {
        $this->revokedAt ??= $now;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
