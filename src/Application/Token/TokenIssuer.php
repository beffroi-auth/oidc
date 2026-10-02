<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\IssuedRefreshToken;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mints what a verified authorization entitles the client to (architecture §4.5, §4.6); whether a
 * refresh token is due, and in which family, is the grant's decision.
 *
 * What the response carries beside the access token is what the authorization can answer for: an ID token
 * describes who signed in, so an authorization with nobody behind it is answered with an access token and
 * nothing else (RFC 6749 §4.4.3). The authorization says which it is by what it is, never by the name of
 * the grant that produced it.
 */
final readonly class TokenIssuer
{
    public function __construct(
        private AccessTokenIssuerInterface $accessTokens,
        private IdTokenIssuerInterface $idTokens,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private SecretDrawer $secrets,
        private EventDispatcherInterface $events,
        private DateInterval $refreshTokenLifetime = new DateInterval('P30D'),
    ) {
    }

    public function refreshToken(RefreshTokenFamily $family, UserAuthorizationInterface $authorization, DateTimeImmutable $now): IssuedRefreshToken
    {
        $value = $this->secrets->draw();
        $token = RefreshToken::fromAuthorization(DrawnSecret::digestOf($value), $family, $authorization, $now, $now->add($this->refreshTokenLifetime));
        $this->refreshTokens->save($token);

        return new IssuedRefreshToken($token, $value);
    }

    /**
     * The ID token is issued when "openid" is among the scopes (OIDC Core §3.1.3.3, §12.2).
     */
    public function issue(
        AuthorizationInterface $authorization,
        ?IssuedRefreshToken $refreshToken,
        RequestContext $context,
        DateTimeImmutable $now,
    ): IssuedTokens {
        $accessToken = $this->accessTokens->issue($authorization, $now);
        $idToken = $this->idToken($authorization, $accessToken, $now);
        $this->events->dispatch(new TokensIssued(
            $now,
            $authorization->tenant,
            $authorization->grantType,
            $authorization->grantId,
            $authorization->client->registration->clientId,
            $authorization instanceof UserAuthorizationInterface ? $authorization->session->id : null,
            $authorization->grantedScopes,
            $accessToken->expiresAt,
            $idToken !== null,
            $authorization->confirmation,
            $refreshToken?->token->tokenHash,
            $context,
        ));

        return new IssuedTokens($authorization, $accessToken, $idToken, $refreshToken);
    }

    /**
     * OIDC Core §3.1.3.3, §12.2: "openid" among the scopes, and somebody to describe. A grant with nobody
     * behind it never has one (RFC 6749 §4.4.3), and the scopes it may ask for say so too.
     */
    private function idToken(AuthorizationInterface $authorization, AccessToken $accessToken, DateTimeImmutable $now): ?string
    {
        if (! $authorization instanceof UserAuthorizationInterface || ! $authorization->scopes->has(Scope::openid())) {
            return null;
        }

        return $this->idTokens->issue($authorization, $accessToken, $now);
    }
}
