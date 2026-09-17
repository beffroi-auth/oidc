<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Revocation;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\TokenRevoked;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnsupportedTokenTypeException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokenInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use function str_contains;

/**
 * The revocation endpoint (RFC 7009 §2, architecture §4.12): a client gives a token back, and the
 * provider stops honouring it at once. The client is authenticated first, the way the token endpoint
 * authenticates it; a public client may revoke what it holds (§2.1), it is its token. Then the token is
 * looked up as a stored access token, then as a refresh token, and revoked when it was issued to the
 * caller. A refresh token takes with it the stored access tokens of its grant (§2.1: "SHOULD also
 * invalidate all access tokens based on the same authorization grant") when the store can; the family
 * is not revoked, a rotated predecessor is already dead and a reuse of it is still told apart.
 *
 * A token the provider cannot find, and a token of another client, are answered 200 without a word
 * (§2.2: "invalid tokens do not cause an error response since the client cannot handle such an error in
 * a reasonable way"), which is also what keeps this endpoint from telling whether a token exists. An
 * access token the provider cannot take back is refused with unsupported_token_type (§2.2.1): the
 * self-contained one, which nothing stores, and a stored one whose store does not revoke
 * (CanRevokeAccessTokenInterface); nothing here pretends a token stopped working. "token_type_hint" is
 * read as a string and then ignored: both stores are consulted.
 */
final readonly class RevocationHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private AccessTokenVerifier $verifier,
        private AccessTokenRepositoryInterface $accessTokens,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the decoded application/x-www-form-urlencoded body
     *
     * @throws OAuth2Exception invalid_client, invalid_request or unsupported_token_type
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context): void
    {
        $caller = $this->clients->authenticate($tenant, $authorizationHeader, $parameters, $context);
        $request = new TokenRequest($parameters);
        $token = $request->required('token');
        $request->optional('token_type_hint');
        $now = $context->receivedAt;
        if (str_contains($token, '.')) {
            $this->refuseSelfContained($tenant, $token, $now);

            return;
        }
        $accessToken = $this->accessTokens->find($token);
        if ($accessToken !== null) {
            $this->revokeAccessToken($accessToken, $caller, $context, $now);

            return;
        }
        $refreshToken = $this->refreshTokens->findByTokenHash(RefreshToken::hash($token));
        if ($refreshToken !== null) {
            $this->revokeRefreshToken($refreshToken, $caller, $context, $now);
        }
    }

    /**
     * A JWS that verifies as an access token of this provider cannot be revoked; one that does not is
     * an invalid token, answered 200 like any other.
     */
    private function refuseSelfContained(Tenant $tenant, #[SensitiveParameter] string $token, DateTimeImmutable $now): void
    {
        try {
            $this->verifier->verify($tenant, $token, $now);
        } catch (InvalidTokenException) {
            return;
        }
        throw new UnsupportedTokenTypeException('A self-contained access token cannot be revoked; it expires on its own (RFC 7009 section 2.2.1).');
    }

    private function revokeAccessToken(StoredAccessToken $token, Client $caller, RequestContext $context, DateTimeImmutable $now): void
    {
        if (! $token->client->equals($caller)) {
            return;
        }
        if (! $this->accessTokens instanceof CanRevokeAccessTokenInterface) {
            throw new UnsupportedTokenTypeException('This provider does not take access tokens back; they expire on their own (RFC 7009 section 2.2.1).');
        }
        $this->accessTokens->revoke($token);
        $this->events->dispatch(new TokenRevoked($now, $token, $caller, [], $context));
    }

    private function revokeRefreshToken(RefreshToken $token, Client $caller, RequestContext $context, DateTimeImmutable $now): void
    {
        if (! $token->client->equals($caller) || $token->isRevoked()) {
            return;
        }
        $token->revoke($now);
        $this->refreshTokens->save($token);
        $accessTokens = $this->accessTokens instanceof CanRevokeAccessTokensByGrantInterface ? $this->accessTokens->revokeByGrant($token->family->grantId) : [];
        $this->events->dispatch(new TokenRevoked($now, $token, $caller, $accessTokens, $context));
    }
}
