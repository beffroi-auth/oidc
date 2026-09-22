<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Revocation;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
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
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use function str_contains;

/**
 * The revocation endpoint (RFC 7009 §2, architecture §4.12): a stored access token or a refresh token
 * issued to the caller is revoked, a refresh token taking the access tokens of its grant with it (§2.1).
 * An unknown token or another client's is answered 200 without a word (§2.2); an access token the
 * provider cannot take back is unsupported_token_type (§2.2.1). "token_type_hint" is ignored.
 */
final readonly class RevocationHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private AccessTokenVerifier $verifier,
        private AccessTokenRepositoryInterface $accessTokens,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the caller presented at the TLS handshake (RFC 8705 §2)
     *
     * @throws OAuth2Exception invalid_client, invalid_request or unsupported_token_type
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
    ): void {
        $caller = $this->clients->authenticate(
            $tenant,
            $this->endpoints->locate($tenant)->revocation,
            $authorizationHeader,
            $parameters,
            $context,
            $certificate,
        )->client;
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
     * A JWS that verifies cannot be revoked; one that does not is an invalid token, answered 200.
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
        $this->events->dispatch(TokenRevoked::ofAccessToken($now, $token, $caller, $context));
    }

    private function revokeRefreshToken(RefreshToken $token, Client $caller, RequestContext $context, DateTimeImmutable $now): void
    {
        if (! $token->client->equals($caller) || $token->isRevoked()) {
            return;
        }
        $token->revoke($now);
        $this->refreshTokens->save($token);
        $accessTokens = $this->accessTokens instanceof CanRevokeAccessTokensByGrantInterface ? $this->accessTokens->revokeByGrant($token->family->grantId) : [];
        $this->events->dispatch(TokenRevoked::ofRefreshToken($now, $token, $caller, $accessTokens, $context));
    }
}
