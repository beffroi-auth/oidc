<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedIdToken;
use Beffroi\Oidc\Domain\Token\AddressedResponse;
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
use Beffroi\Oidc\Exception\InvalidArgumentException;
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
 * A response is addressed before it is struck, and struck here for what was read (OIDC Core §3.1.3.7,
 * architecture §4.5). What it reads from outside the provider is the key of the tenant each of its tokens is
 * signed with, opened by the KMS, the salt of the tenant the "sub" of a pairwise client is computed with, unsealed
 * by the KMS (OIDC Core §8.1), and the key of the client its ID token is encrypted to, read from what the client
 * publishes. A grant whose authorization somebody signed in for addresses the response before it spends
 * what the request presented: a KMS that does not answer and a set the client cannot serve right now are then
 * errors the same request is served past once they answer, where read after the spending they would cost the
 * client its code, or the family of its refresh token. A response to an authorization nobody signed in for
 * carries an access token and nothing else, and is addressed here when its grant did not address it.
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
     * What a response to an authorization of that client somebody signed in for needs from outside the provider,
     * read now: the key of the tenant its access token is signed with, opened, and, when "openid" is among the
     * scopes (OIDC Core §3.1.3.3), the shape of its ID token with the key of the tenant it is signed with and the
     * key of the client it is encrypted to; and the kind of "sub" the client registered, opened for each token that
     * names the person, which for a pairwise client unseals the salt of its tenant (OIDC Core §8.1). What a grant
     * asks before it spends what the request presented.
     *
     * @throws KeyNotFoundException when the tenant has no active key for an algorithm the response is signed with
     * @throws KmsUnavailableException when the KMS does not answer to open a key the response is signed with, which is not open yet, or the salt of a pairwise client
     * @throws ClientKeysUnavailableException when the set the client publishes cannot be read, or holds no key its ID tokens can be encrypted to
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function address(Client $client, Scopes $scopes): AddressedResponse
    {
        return new AddressedResponse(
            $this->accessTokens->address($client),
            $scopes->has(Scope::openid()) ? $this->idTokens->address($client) : null,
        );
    }

    /**
     * The ID token is issued when "openid" is among the scopes (OIDC Core §3.1.3.3, §12.2), for the shape
     * the grant addressed.
     *
     * @param AddressedResponse|null $addressed what address() answered before the grant spent anything; null for an authorization nobody signed in for whose grant did not address it
     *
     * @throws KeyNotFoundException when the response is addressed here and the tenant has no active key for the algorithm its access token is signed with
     * @throws KmsUnavailableException when the response is addressed here and the KMS does not answer to open the key its access token is signed with
     * @throws LogicException when the response to an authorization somebody signed in for, or the ID token it carries, was not addressed by the grant first
     */
    public function issue(
        AuthorizationInterface $authorization,
        ?IssuedRefreshToken $refreshToken,
        RequestContext $context,
        DateTimeImmutable $now,
        ?AddressedResponse $addressed = null,
    ): IssuedTokens {
        $addressed ??= $this->addressedHere($authorization);
        $accessToken = $this->accessTokens->issue($authorization, $addressed->accessToken, $now);
        $idToken = $this->idToken($authorization, $accessToken, $addressed->idToken, $now);
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
     * The response to an authorization nobody signed in for, addressed right before it is struck: an access token
     * and nothing else (RFC 6749 §4.4.3). One somebody signed in for is addressed by its grant, which may spend
     * what the request presented before it asks for the tokens.
     *
     * @throws KeyNotFoundException when the tenant has no active key for the algorithm the access token is signed with
     * @throws KmsUnavailableException when the KMS does not answer to open that key, which is not open yet
     * @throws LogicException when somebody signed in for the authorization, so that its grant was to address the response
     */
    private function addressedHere(AuthorizationInterface $authorization): AddressedResponse
    {
        if ($authorization instanceof UserAuthorizationInterface) {
            throw new LogicException('The response to an authorization somebody signed in for was not addressed before the grant spent what the request presented (architecture section 4.5).');
        }

        return new AddressedResponse($this->accessTokens->address($authorization->client));
    }

    /**
     * OIDC Core §3.1.3.3, §12.2: "openid" among the scopes, and somebody to describe. A grant with nobody
     * behind it never has one (RFC 6749 §4.4.3), and the scopes it may ask for say so too.
     *
     * @throws LogicException when the token is due and the grant did not address it
     */
    private function idToken(AuthorizationInterface $authorization, AccessToken $accessToken, ?AddressedIdToken $addressed, DateTimeImmutable $now): ?string
    {
        if (! $authorization instanceof UserAuthorizationInterface || ! $authorization->scopes->has(Scope::openid())) {
            return null;
        }

        return $this->idTokens->issue(
            $authorization,
            $accessToken,
            $addressed ?? throw new LogicException('The ID token of this response was not addressed before the grant spent what the request presented (OIDC Core section 3.1.3.7).'),
            $now,
        );
    }
}
