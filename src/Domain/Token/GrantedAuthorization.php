<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_all;
use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What the token endpoint has established the client may receive, once a grant has been verified
 * (architecture §4.5): the client, the session and the user behind it, the scopes of this response and
 * those the resource owner granted, the nonce when the tokens answer an authorization code, the claims
 * requested, and the authentication as it stood when the user authorized ("auth_time", "amr", "acr").
 * The issuers of the access token and of the ID token read it; nothing else does.
 *
 * "scopes" is what this response carries, "grantedScopes" what the user granted: a refresh may narrow
 * the former (RFC 6749 §6), the refresh token keeps the latter.
 */
final readonly class GrantedAuthorization
{
    public Tenant $tenant;

    public User $user;

    /**
     * @var non-empty-list<Scope>
     */
    public array $scopes;

    /**
     * @var non-empty-list<Scope>
     */
    public array $grantedScopes;

    /**
     * @var non-empty-list<string> the "amr" values
     */
    public array $authenticationMethods;

    /**
     * @param list<Scope> $scopes the scopes of this response, at least one, all among the granted ones
     * @param list<Scope> $grantedScopes the scopes the resource owner granted
     * @param string|null $nonce the one of the authorization request, only when the tokens answer a code (OIDC Core §3.1.3.7 step 11, §12.2)
     * @param list<string> $authenticationMethods the "amr" values, at least one
     */
    public function __construct(
        public GrantType $grantType,
        public Client $client,
        public AuthenticationSession $session,
        array $scopes,
        array $grantedScopes,
        public ?string $nonce,
        public ?ClaimsRequest $claimsRequest,
        public DateTimeImmutable $authenticatedAt,
        array $authenticationMethods,
        public ?string $authenticationContextClass,
    ) {
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization binds a session and a client of the same tenant.');
        }
        if ($scopes === [] || $grantedScopes === []) {
            throw new InvalidArgumentException('An authorization carries at least one scope.');
        }
        if (! array_all($scopes, static fn (Scope $scope): bool => array_any($grantedScopes, static fn (Scope $granted): bool => $granted->equals($scope)))) {
            throw new InvalidArgumentException('The scopes of a response are among the granted ones (RFC 6749 section 6).');
        }
        if ($authenticationMethods === []) {
            throw new InvalidArgumentException('An authorization records at least one authentication method (RFC 8176).');
        }
        if ($grantType === GrantType::RefreshToken && $nonce !== null) {
            throw new InvalidArgumentException('An ID token issued on a refresh carries no nonce (OIDC Core section 12.2).');
        }
        $this->tenant = $client->tenant;
        $this->user = $session->user;
        $this->scopes = $scopes;
        $this->grantedScopes = $grantedScopes;
        $this->authenticationMethods = $authenticationMethods;
    }

    /**
     * RFC 6749 §4.1.3, OIDC Core §3.1.3: everything the code recorded, scopes included.
     */
    public static function fromAuthorizationCode(AuthorizationCode $code): self
    {
        return new self(
            GrantType::AuthorizationCode,
            $code->client,
            $code->session,
            $code->scopes,
            $code->scopes,
            $code->nonce,
            $code->claimsRequest,
            $code->authenticatedAt,
            $code->authenticationMethods,
            $code->authenticationContextClass,
        );
    }

    /**
     * RFC 6749 §6: the scopes of the token, or the narrower ones the client asked for; no nonce.
     *
     * @param list<Scope>|null $scopes the scopes requested, null for the ones of the token
     */
    public static function fromRefreshToken(RefreshToken $token, ?array $scopes): self
    {
        return new self(
            GrantType::RefreshToken,
            $token->client,
            $token->session,
            $scopes ?? $token->scopes,
            $token->scopes,
            null,
            $token->claimsRequest,
            $token->authenticatedAt,
            $token->authenticationMethods,
            $token->authenticationContextClass,
        );
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}
