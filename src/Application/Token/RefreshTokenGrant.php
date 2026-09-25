<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RevokedTokenHashes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 6749 §6, RFC 9700 §4.13 (architecture §4.5): what tells a refresh token from a copy of itself is
 * the authentication of a confidential client, the key or the certificate it is bound to, or rotation,
 * and one of the three is enough (§4.13.2). A token that is protected by neither of the first two is
 * rotated on every use, its successor in the same family with the same scopes, and presented again it
 * revokes the family; a token that is protected otherwise stands, because replacing it would add
 * nothing and would lock out a client that lost the answer (FAPI 2.0 Security Profile §5.3.2.1-9).
 * The session may have expired, not have been ended (architecture §4.9).
 *
 * A token bound to a key (RFC 9449 §5) is refreshed by a request that proves that key again, and by
 * nobody else: the client that holds it is a public client, and the binding is the whole of what tells
 * it from whoever took a copy of the token.
 */
final readonly class RefreshTokenGrant implements SpendsRefreshTokensInterface
{
    private const string INVALID = 'The refresh token is invalid.';

    public function __construct(
        private RefreshTokenRepositoryInterface $refreshTokens,
        private RefreshTokenRevocation $revocation,
        private TokenIssuer $issuer,
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

        $token = $this->refreshTokens->findByTokenHash(RefreshToken::hash($value));
        if ($token === null || ! $token->client->equals($client->client) || $token->isRevoked()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isRotated()) {
            $this->reused($token, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isExpired($now) || $token->session->hasEnded() || ! $token->isRefreshedBy($client->confirmation)) {
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
        );
        if (! $token->rotatesOnUse()) {
            return $this->issuer->issue($authorization, null, $context, $now);
        }
        $token->rotate($now);
        $this->refreshTokens->save($token);
        $successor = $this->issuer->refreshToken($token->family, $authorization, $now);
        $this->events->dispatch(new RefreshTokenRotated(
            $successor->token->issuedAt,
            $successor->token->tenant,
            $successor->token->clientId,
            $successor->token->family->id,
            $token->tokenHash,
            $successor->token->tokenHash,
            $successor->token->expiresAt,
            $context,
        ));

        return $this->issuer->issue($authorization, $successor, $context, $now);
    }

    /**
     * RFC 6749 §3.3, without repeats.
     *
     * @throws InvalidScopeException when the parameter is not a list of scope tokens
     *
     * @return Scopes|null null when the client did not narrow the scope
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
     * RFC 9700 §4.13.2.
     */
    private function reused(RefreshToken $presented, RequestContext $context, DateTimeImmutable $now): void
    {
        $revoked = $this->revocation->revokeFamily($presented->family->id, $now);
        $this->events->dispatch(new RefreshTokenReuseDetected(
            $now,
            $presented->tenant,
            $presented->clientId,
            $presented->family->id,
            $presented->tokenHash,
            RevokedTokenHashes::of($revoked),
            $context,
        ));
    }
}
