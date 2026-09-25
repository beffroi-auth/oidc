<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\IssuedRefreshToken;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mints what a verified authorization entitles the client to (architecture §4.5, §4.6); whether a
 * refresh token is due, and in which family, is the grant's decision.
 */
final readonly class TokenIssuer
{
    public function __construct(
        private AccessTokenIssuerInterface $accessTokens,
        private IdTokenIssuerInterface $idTokens,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private EventDispatcherInterface $events,
        private DateInterval $refreshTokenLifetime = new DateInterval('P30D'),
    ) {
    }

    public function refreshToken(RefreshTokenFamily $family, GrantedAuthorization $authorization, DateTimeImmutable $now): IssuedRefreshToken
    {
        $value = RefreshToken::generate();
        $token = RefreshToken::fromAuthorization(RefreshToken::hash($value), $family, $authorization, $now, $now->add($this->refreshTokenLifetime));
        $this->refreshTokens->save($token);

        return new IssuedRefreshToken($token, $value);
    }

    /**
     * The ID token is issued when "openid" is among the scopes (OIDC Core §3.1.3.3, §12.2).
     */
    public function issue(GrantedAuthorization $authorization, ?IssuedRefreshToken $refreshToken, RequestContext $context, DateTimeImmutable $now): IssuedTokens
    {
        $accessToken = $this->accessTokens->issue($authorization, $now);
        $idToken = $authorization->scopes->has(Scope::openid()) ? $this->idTokens->issue($authorization, $accessToken, $now) : null;
        $this->events->dispatch(new TokensIssued(
            $now,
            $authorization->tenant,
            $authorization->grantType,
            $authorization->grantId,
            $authorization->client->registration->clientId,
            $authorization->session->id,
            $authorization->grantedScopes,
            $accessToken->expiresAt,
            $idToken !== null,
            $authorization->confirmation,
            $refreshToken?->token->tokenHash,
            $context,
        ));

        return new IssuedTokens($authorization, $accessToken, $idToken, $refreshToken);
    }
}
