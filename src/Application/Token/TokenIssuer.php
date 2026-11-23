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
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A grant addresses the response, reading what it needs from the KMS and the client, before it spends what the
 * request presented: an outage then leaves the request to be presented again.
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
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws ClientKeysUnavailableException
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
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws LogicException when somebody signed in for the authorization, whose grant calls address() instead
     */
    public function addressFor(AuthorizationInterface $authorization): AddressedResponse
    {
        if ($authorization instanceof UserAuthorizationInterface) {
            throw new LogicException('The response to an authorization somebody signed in for was not addressed before the grant spent what the request presented (architecture section 4.5).');
        }

        return new AddressedResponse($this->accessTokens->addressFor($authorization));
    }

    /**
     * OIDC Core §3.1.3.3, §12.2
     *
     * @param AddressedResponse|null $addressed null only when nobody signed in and the grant spends nothing
     *
     * @throws KeyNotFoundException when the response is addressed here
     * @throws KmsUnavailableException when the response is addressed here
     * @throws LogicException when a response somebody signed in for was not addressed by its grant first
     * @throws InvalidTargetException when the access token is addressed to the administration API and the authorization holds to less than its reservation (decision 0038)
     * @throws ClientKeysUnavailableException when the key the ID token is addressed to receives no JWE
     */
    public function issue(
        AuthorizationInterface $authorization,
        ?IssuedRefreshToken $refreshToken,
        RequestContext $context,
        DateTimeImmutable $now,
        ?AddressedResponse $addressed = null,
    ): IssuedTokens {
        $addressed ??= $this->addressFor($authorization);
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
            $authorization instanceof UserAuthorizationInterface ? $authorization->claimsRequest : null,
            $authorization instanceof UserAuthorizationInterface ? $authorization->authorizationDetails : null,
            $authorization->client->registration->accessTokenShape->name(),
            $context,
        ));

        return new IssuedTokens($authorization, $accessToken, $idToken, $refreshToken);
    }

    /**
     * OIDC Core §3.1.3.3, §12.2
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
