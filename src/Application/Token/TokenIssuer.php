<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\IssuedRefreshToken;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\LogicException;
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
 *
 * An ID token is addressed by the grant before it spends what the request presented, and struck here for
 * what was read (OIDC Core §3.1.3.7): the key of the client it is encrypted to is the one thing of the
 * response read from outside the provider, so a set the client cannot serve right now is an error the
 * same request is served past once it can, where read after the spending it would cost the client its
 * code, or the family of its refresh token.
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
     * The shape of the ID token a response to an authorization somebody signed in for carries, with the key
     * of the client it is encrypted to when it registered an encryption, read now: what a grant asks before
     * it spends what the request presented.
     *
     * @return AddressedFormat|null null when the response carries no ID token, "openid" not among the scopes (OIDC Core §3.1.3.3)
     *
     * @throws ClientKeysUnavailableException when the set the client publishes cannot be read, or holds no key its ID tokens can be encrypted to
     */
    public function addressIdToken(Client $client, Scopes $scopes): ?AddressedFormat
    {
        if (! $scopes->has(Scope::openid())) {
            return null;
        }

        return $this->idTokens->address($client);
    }

    /**
     * The ID token is issued when "openid" is among the scopes (OIDC Core §3.1.3.3, §12.2), for the shape
     * the grant addressed.
     *
     * @param AddressedFormat|null $idTokenFormat what addressIdToken() answered before the grant spent anything; null for an authorization nobody signed in for
     *
     * @throws LogicException when the response carries an ID token the grant did not address first
     */
    public function issue(
        AuthorizationInterface $authorization,
        ?IssuedRefreshToken $refreshToken,
        RequestContext $context,
        DateTimeImmutable $now,
        ?AddressedFormat $idTokenFormat = null,
    ): IssuedTokens {
        $accessToken = $this->accessTokens->issue($authorization, $now);
        $idToken = $this->idToken($authorization, $accessToken, $idTokenFormat, $now);
        $this->events->dispatch(new TokensIssued(
            $now,
            $authorization->tenant,
            $authorization->grantType,
            $authorization->grantId,
            $authorization->client->registration->clientId,
            $authorization->person(),
            $authorization instanceof UserAuthorizationInterface ? $authorization->session->id : null,
            $authorization->grantedScopes,
            $accessToken->expiresAt,
            $idToken !== null,
            $authorization->confirmation,
            $refreshToken?->token->tokenHash,
            // what the client is given of the person, which the row beside the act holds (issue #590): a
            // grant nobody was asked for carries neither a request by name nor details anybody agreed to
            $authorization instanceof UserAuthorizationInterface ? $authorization->claimsRequest : null,
            $authorization instanceof UserAuthorizationInterface ? $authorization->authorizationDetails : null,
            $authorization->client->registration->accessTokenShape->name(),
            $context,
        ));

        return new IssuedTokens($authorization, $accessToken, $idToken, $refreshToken);
    }

    /**
     * OIDC Core §3.1.3.3, §12.2: "openid" among the scopes, and somebody to describe. A grant with nobody
     * behind it never has one (RFC 6749 §4.4.3), and the scopes it may ask for say so too.
     *
     * @throws LogicException when the token is due and the grant did not address it
     */
    private function idToken(AuthorizationInterface $authorization, AccessToken $accessToken, ?AddressedFormat $format, DateTimeImmutable $now): ?string
    {
        if (! $authorization instanceof UserAuthorizationInterface || ! $authorization->scopes->has(Scope::openid())) {
            return null;
        }

        return $this->idTokens->issue(
            $authorization,
            $accessToken,
            $format ?? throw new LogicException('The ID token of this response was not addressed before the grant spent what the request presented (OIDC Core section 3.1.3.7).'),
            $now,
        );
    }
}
