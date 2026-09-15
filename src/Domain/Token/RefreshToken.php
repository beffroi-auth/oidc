<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_all;
use function array_any;
use function base64_encode;
use DateTimeImmutable;
use function hash;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function min;
use function preg_match;
use function random_bytes;
use function rtrim;
use SensitiveParameter;
use function strtr;

/**
 * A refresh token (RFC 6749 §1.5, §6) as the provider keeps it: the SHA-256 of the opaque value the
 * client received, its family, and everything the next refresh needs (architecture §4.6). The
 * authentication is the one of the original authorization, copied from the code and carried along the
 * rotations, because the ID token issued on a refresh describes that authentication, not a later
 * step-up (OIDC Core §12.2).
 *
 * A token is presented once: the rotation marks it and issues its successor in the same family; a
 * second presentation is a reuse, and the grant revokes the family (RFC 9700 §4.13.2). The scopes are
 * those the resource owner granted; a refresh may narrow what a response carries, never what the token
 * keeps (RFC 6749 §6).
 */
final class RefreshToken
{
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
     * @param string $tokenHash hex SHA-256 of the token, see hash()
     * @param list<Scope> $scopes the scopes granted, at least one
     * @param DateTimeImmutable $authenticatedAt the "auth_time" of the original authentication
     * @param list<string> $authenticationMethods the "amr" values, at least one
     * @param string|null $authenticationContextClass the "acr" value
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
        public readonly ?string $authenticationContextClass,
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
        $this->scopes = $scopes;
        $this->authenticationMethods = $authenticationMethods;
    }

    /**
     * The token a grant issues: what the resource owner granted, as the authorization records it, with
     * the sliding expiry capped by the family.
     */
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
     * A fresh token: 256 bits from the CSPRNG, base64url without padding (43 characters).
     */
    public static function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * How a token is stored and looked up: a leaked table of tokens yields nothing usable.
     */
    public static function hash(#[SensitiveParameter] string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13.2: the token was presented and replaced. The grant reads isRotated()
     * before calling this: a second presentation is a reuse, not a state error.
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
     * The first revocation wins: a token revoked with its family and then swept keeps the date it
     * stopped applying.
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
     * The token's own expiry is never past the one of the family, so this covers both.
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
