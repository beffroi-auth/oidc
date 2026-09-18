<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_all;
use function array_any;
use DateTimeImmutable;
use function hash;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function min;
use function preg_match;
use function random_bytes;
use SensitiveParameter;

/**
 * A refresh token (RFC 6749 §6, architecture §4.6) as the provider keeps it: the SHA-256 of the value,
 * its family, the authentication of the original authorization carried along the rotations (OIDC Core
 * §12.2). Presented once; a second presentation is a reuse (RFC 9700 §4.13.2).
 */
final class RefreshToken
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * @var non-empty-list<Scope>
     */
    public readonly array $scopes;

    /**
     * @var non-empty-list<string> the "amr" values
     */
    public readonly array $authenticationMethods;

    public private(set) ?DateTimeImmutable $rotatedAt = null;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param string $tokenHash see hash()
     * @param list<Scope> $scopes at least one
     * @param list<string> $authenticationMethods the "amr" values, at least one
     * @param string $authenticationContextClass the "acr" value
     * @param DateTimeImmutable $expiresAt the sliding expiry, never past the one of the family
     */
    public function __construct(
        public readonly string $tokenHash,
        public readonly RefreshTokenFamily $family,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        array $scopes,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly DateTimeImmutable $authenticatedAt,
        array $authenticationMethods,
        public readonly string $authenticationContextClass,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (preg_match(AuthorizationCode::HASH_PATTERN, $tokenHash) !== 1) {
            throw new InvalidArgumentException('A refresh token is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('A refresh token binds a session and a client of the same tenant.');
        }
        if ($scopes === []) {
            throw new InvalidArgumentException('A refresh token grants at least one scope.');
        }
        if ($authenticationMethods === []) {
            throw new InvalidArgumentException('A refresh token records at least one authentication method (RFC 8176).');
        }
        if ($issuedAt < $family->startedAt) {
            throw new InvalidArgumentException('A refresh token is issued after its family started.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A refresh token expires after it was issued.');
        }
        if ($expiresAt > $family->expiresAt) {
            throw new InvalidArgumentException('A refresh token never outlives its family.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->clientId;
        $this->scopes = $scopes;
        $this->authenticationMethods = $authenticationMethods;
    }

    public static function fromAuthorization(string $tokenHash, RefreshTokenFamily $family, GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): self
    {
        return new self(
            $tokenHash,
            $family,
            $authorization->client,
            $authorization->session,
            $authorization->grantedScopes,
            $authorization->claimsRequest,
            $authorization->authenticatedAt,
            $authorization->authenticationMethods,
            $authorization->authenticationContextClass,
            $now,
            min($expiresAt, $family->expiresAt),
        );
    }

    /**
     * 256 bits, base64url without padding.
     */
    public static function generate(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    public static function hash(#[SensitiveParameter] string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13.2. The grant reads isRotated() first: a second presentation is a reuse.
     */
    public function rotate(DateTimeImmutable $now): void
    {
        if ($this->rotatedAt !== null) {
            throw new LogicException('A refresh token is rotated once; the grant checks isRotated() first.');
        }
        if ($this->revokedAt !== null) {
            throw new LogicException('A revoked refresh token is not rotated.');
        }
        $this->rotatedAt = $now;
    }

    /**
     * The first revocation wins.
     */
    public function revoke(DateTimeImmutable $now): void
    {
        if ($this->revokedAt !== null) {
            return;
        }
        $this->revokedAt = $now;
    }

    public function isRotated(): bool
    {
        return $this->rotatedAt !== null;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /**
     * Never past the expiry of the family.
     */
    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * @param list<Scope> $scopes
     */
    public function covers(array $scopes): bool
    {
        return array_all($scopes, fn (Scope $scope): bool => $this->hasScope($scope));
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}
