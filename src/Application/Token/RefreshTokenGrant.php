<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Port\SubjectsOfSessionsInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Beffroi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RevokedTokenHashes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 6749 §6, RFC 9700 §4.14
 *
 * Only a token protected by neither client authentication nor a binding is rotated: rotating another would lock
 * out a client that lost the answer (FAPI 2.0 Security Profile §5.3.2.1-9). What the KMS opens is read before the
 * token is rotated, so a KMS that does not answer leaves the token as it was.
 */
final readonly class RefreshTokenGrant implements SpendsRefreshTokensInterface
{
    private const string INVALID = 'The refresh token is invalid.';

    public function __construct(
        private RefreshTokenRepositoryInterface $refreshTokens,
        private RefreshTokenRevocation $revocation,
        private SubjectsOfSessionsInterface $subjects,
        private TokenIssuer $issuer,
        private RequestedAuthorizationDetails $authorizationDetails,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName('refresh_token');
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $value = $request->required('refresh_token');
        $scopes = self::scopes($request->optional('scope'));

        $token = $this->refreshTokens->findByTokenHash(DrawnSecret::digestOf($value));
        if ($token === null || ! $token->client->equals($client->client) || $token->isRevoked()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isRotated()) {
            $this->reused($token, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }
        $sessionEndedAt = $token->session->endedAt;
        if ($sessionEndedAt !== null) {
            $this->events->dispatch(new RefreshTokenOutlivedItsSession(
                $now,
                $token->tenant,
                $token->clientId,
                $token->session->user->subject,
                $token->session->id,
                $sessionEndedAt,
                $context,
            ));

            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isExpired($now) || ! $token->isRefreshedBy($client->confirmation) || ! $token->session->user->isEnabled()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($scopes !== null && ! $token->scopes->covers($scopes)) {
            throw new InvalidScopeException('The requested scope exceeds the scope granted to the refresh token (RFC 6749 section 6).');
        }

        $authorization = UserAuthorization::fromRefreshToken(
            $this->grantType(),
            $token,
            $scopes,
            $client->confirmation,
            RequestedResources::of($request, $token->resources),
            $this->authorizationDetails->of($request, $token->authorizationDetails),
        );
        $addressed = $this->issuer->address($authorization->client, $authorization->scopes);
        $person = $authorization->person();
        if (! $token->rotatesOnUse()) {
            return $this->issuer->issue($authorization, null, $context, $now, $addressed);
        }
        $token->rotate($now);
        $this->refreshTokens->save($token);
        $successor = $this->issuer->refreshToken($token->family, $authorization, $now);
        $this->events->dispatch(new RefreshTokenRotated(
            $successor->token->issuedAt,
            $successor->token->tenant,
            $successor->token->clientId,
            $person,
            $successor->token->family->id,
            $token->tokenHash,
            $successor->token->tokenHash,
            $successor->token->expiresAt,
            $context,
        ));

        return $this->issuer->issue($authorization, $successor, $context, $now, $addressed);
    }

    /**
     * RFC 6749 §3.3
     *
     * @throws InvalidScopeException
     */
    private static function scopes(?string $scope): ?Scopes
    {
        if ($scope === null) {
            return null;
        }
        try {
            return Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
        }
    }

    /**
     * RFC 9700 §4.14.2
     *
     * The person is named by the subject the store of sessions keeps in the clear, so the KMS need not answer.
     */
    private function reused(RefreshToken $presented, RequestContext $context, DateTimeImmutable $now): void
    {
        $revoked = $this->revocation->revokeFamily($presented->family->id, $now);
        $this->events->dispatch(new RefreshTokenReuseDetected(
            $now,
            $presented->tenant,
            $presented->clientId,
            $this->subjects->of($presented->session->id),
            $presented->family->id,
            $presented->tokenHash,
            RevokedTokenHashes::of($revoked),
            $context,
        ));
    }
}
