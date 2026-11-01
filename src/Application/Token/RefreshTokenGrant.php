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
 * RFC 6749 §6, RFC 9700 §4.13 (architecture §4.5): what tells a refresh token from a copy of itself is
 * the authentication of a confidential client, the key or the certificate it is bound to, or rotation,
 * and one of the three is enough (§4.13.2). A token that is protected by neither of the first two is
 * rotated on every use, its successor in the same family with the same scopes, and presented again it
 * revokes the family; a token that is protected otherwise stands, because replacing it would add
 * nothing and would lock out a client that lost the answer (FAPI 2.0 Security Profile §5.3.2.1-9).
 * The session may have expired, not have been ended (decision 0031). A token of a session that has ended is
 * refused, and announced (RefreshTokenOutlivedItsSession): the tokens of a session are revoked on the lane of the
 * events, so a refresh in flight when it ended may have saved its successor after they were, and that successor is
 * revoked once its first use is handled. A token revoked is refused before its session is read, so a row is no
 * longer announced once that revocation has run, and announcing it again before is harmless.
 *
 * What the request may narrow it narrows and never widens: the scopes of the response (RFC 6749 §6), the
 * resources its access token is addressed to (RFC 8707 §2.2) and the details it carries (RFC 9396 §7), the
 * refresh token beside it staying bound to the whole of the original grant in each case.
 *
 * A token bound to a key (RFC 9449 §5) is refreshed by a request that proves that key again, and by
 * nobody else: the client that holds it is a public client, and the binding is the whole of what tells
 * it from whoever took a copy of the token.
 *
 * What the response reads from outside the provider is read before the token is rotated (architecture
 * §4.5): the keys of the tenant its tokens are signed with, opened by the KMS, the key the ID token is
 * encrypted to (OIDC Core §3.1.3.7), and the session the token descends from and the person it names, rows
 * a store opens under the data keys of the tenant (decision 0018), the person being what the announcement of
 * the rotation names. A KMS that does not answer, or keys the client cannot serve right now, leave the token
 * as it was, where a token rotated and then left unanswered would make the next presentation a reuse, and
 * revoke the family. A rotated token presented again reads nothing before its family is revoked, and the reuse
 * is announced with the person named by the subject the store of sessions keeps in the clear (decision 0011):
 * the family is revoked, and its revocation announced, whatever the KMS answers.
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
        if ($token->isExpired($now) || ! $token->isRefreshedBy($client->confirmation)) {
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
     * RFC 9700 §4.13.2: the family is revoked, and the reuse announced with it. The person is named by the subject
     * the store of sessions keeps in the clear and not read from the session, which a store that has not opened it
     * yet would open under the data keys of the tenant (issue #884).
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
