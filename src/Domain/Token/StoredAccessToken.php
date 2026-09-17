<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token as the provider keeps it (architecture §4.6): the SHA-256 of the random value
 * the client received, and everything a resource of the provider or the introspection endpoint (RFC 7662)
 * answers with: the client, the session and the user behind it, the grant the token descends from, the
 * scopes of the response, the claims asked for by name (OIDC Core §5.5), the authentication as it stood
 * when the user authorized ("auth_time", "amr", "acr"), and the two dates. The same facts a self-contained
 * token carries as claims, kept here instead, so that the token itself tells whoever holds it nothing.
 *
 * The record is written once and never changes: the repository draws the value, keeps the record under
 * its hash, and removes it when the token is revoked, with the session it descends from (a logout), with
 * the grant (a replayed code, RFC 6749 §4.1.2), or by the client at the revocation endpoint (RFC 7009).
 * A revoked token is then an unknown one, which is all a bearer token needs to be refused (RFC 6750 §3.1).
 */
final readonly class StoredAccessToken
{
    public Tenant $tenant;

    /**
     * The client, named the way a registration names it: the object is what the client repository resolved
     * for that identifier, and what a store keeps is the identifier.
     */
    public string $clientId;

    /**
     * @var non-empty-list<Scope>
     */
    public array $scopes;

    /**
     * @var non-empty-list<string> the "amr" values
     */
    public array $authenticationMethods;

    /**
     * @param string $tokenHash hex SHA-256 of the token, see OpaqueTokenValue::hash()
     * @param Uuid $grantId the authorization code the token descends from, what the replay of that code revokes
     * @param list<Scope> $scopes the scopes of the response, at least one
     * @param DateTimeImmutable $authenticatedAt the "auth_time" of the original authentication
     * @param list<string> $authenticationMethods the "amr" values, at least one
     * @param string $authenticationContextClass the "acr" value, the class of the session when the user authorized
     */
    public function __construct(
        public string $tokenHash,
        public Uuid $grantId,
        public Client $client,
        public AuthenticationSession $session,
        array $scopes,
        public ?ClaimsRequest $claimsRequest,
        public DateTimeImmutable $authenticatedAt,
        array $authenticationMethods,
        public string $authenticationContextClass,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if (preg_match(AuthorizationCode::HASH_PATTERN, $tokenHash) !== 1) {
            throw new InvalidArgumentException('An opaque access token is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An access token binds a session and a client of the same tenant.');
        }
        if ($scopes === []) {
            throw new InvalidArgumentException('An access token carries at least one scope.');
        }
        if ($authenticationMethods === []) {
            throw new InvalidArgumentException('An access token records at least one authentication method (RFC 8176).');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->clientId;
        $this->scopes = $scopes;
        $this->authenticationMethods = $authenticationMethods;
    }

    /**
     * The record of a token the issuer mints: the scopes of this response, and the authentication as the
     * authorization records it.
     */
    public static function fromAuthorization(string $tokenHash, GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): self
    {
        return new self(
            $tokenHash,
            $authorization->grantId,
            $authorization->client,
            $authorization->session,
            $authorization->scopes,
            $authorization->claimsRequest,
            $authorization->authenticatedAt,
            $authorization->authenticationMethods,
            $authorization->authenticationContextClass,
            $now,
            $expiresAt,
        );
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}
