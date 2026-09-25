<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_any;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.1.3, RFC 7636 §4.6, OIDC Core §3.1.3 (architecture §4.5). Every failure is "invalid_grant"
 * with one description. The code is consumed by its first presentation (RFC 9700 §4.5); presented again,
 * the grant and every token descending from it are revoked (RFC 6749 §4.1.2).
 *
 * A code reserved for a key (RFC 9449 §10) is exchanged by a request that proves that key and by no
 * other: the authorization request said which key would come and collect it, and a code intercepted on
 * its way back through the browser is worth nothing to whoever does not hold it.
 */
final readonly class AuthorizationCodeGrant implements IssuesRefreshTokensInterface
{
    private const string INVALID = 'The authorization code is invalid.';

    /**
     * @param ServedGrantsInterface $servedGrants what the provider serves, read for the grants that spend a refresh token: this one issues none the client could not spend
     * @param DateInterval $refreshTokenFamilyLifetime the absolute lifetime no rotation extends (architecture §4.6)
     */
    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private RefreshTokenRevocation $refreshTokens,
        private AccessTokenRepositoryInterface $accessTokens,
        private TokenIssuer $issuer,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private ServedGrantsInterface $servedGrants,
        private DateInterval $refreshTokenFamilyLifetime = new DateInterval('P90D'),
        private bool $refreshTokenWithoutOfflineAccess = true,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName('authorization_code');
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $code = $request->required('code');
        $redirectUri = $request->required('redirect_uri');
        $codeVerifier = $request->optional('code_verifier');
        if ($codeVerifier !== null && ! CodeChallenge::hasTheShape($codeVerifier)) {
            throw new InvalidRequestException('The code_verifier parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.1).');
        }

        $record = $this->codes->findByCodeHash(AuthorizationCode::hash($code));
        if ($record === null) {
            throw new InvalidGrantException(self::INVALID);
        }
        // atomic: of the requests presenting this code at once, exactly one is the first
        if (! $this->codes->consume($record, $now)) {
            $this->replayed($record, $client->client, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }

        if (
            ! $record->client->equals($client->client)
            || $record->isExpired($now)
            || ! $record->redirectUri->matches($redirectUri)
            || ! self::pkceSatisfied($record, $codeVerifier)
            || ! self::reservationSatisfied($record, $client)
            || ! $record->session->isActive($now)
        ) {
            throw new InvalidGrantException(self::INVALID);
        }

        // RFC 8707 §2.2: the access token of this response may be addressed to a subset of the
        // resources the authorization carries, while the refresh token beside it stays bound to them all
        $authorization = GrantedAuthorization::fromAuthorizationCode(
            $this->grantType(),
            $record,
            $client->confirmation,
            RequestedResources::of($request, $record->resources),
        );
        $refreshToken = null;
        if ($this->refreshTokenDue($authorization)) {
            $family = new RefreshTokenFamily(Uuid::v7(), $record->codeHash, $record->grantId, $now, $now->add($this->refreshTokenFamilyLifetime));
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now);
    }

    /**
     * RFC 7636 §4.6 when the code carries a challenge, RFC 9700 §4.8.2 when it carries none.
     */
    private static function pkceSatisfied(AuthorizationCode $record, #[SensitiveParameter] ?string $codeVerifier): bool
    {
        if ($record->codeChallenge === null) {
            return $codeVerifier === null;
        }

        return $codeVerifier !== null && $record->codeChallenge->verifies($codeVerifier);
    }

    /**
     * RFC 9449 §10.1: a code the authorization request reserved for a key is exchanged by a request that
     * proved that key. A code reserved for none is exchanged by whichever request the rest of this
     * grant accepts, a client that binds no token being a client that reserves nothing.
     */
    private static function reservationSatisfied(AuthorizationCode $record, AuthenticatedClient $client): bool
    {
        return $record->dpopKey === null || $client->confirmation !== null && $client->confirmation->matches($record->dpopKey);
    }

    /**
     * RFC 6749 §4.1.4, OIDC Core §11: a refresh token this client could not spend is one this response
     * does not carry. What spends one is what the provider is wired with and the client registered for,
     * and neither this grant nor the client names it.
     */
    private function refreshTokenDue(GrantedAuthorization $authorization): bool
    {
        $registration = $authorization->client->registration;
        $spent = array_any(
            $this->servedGrants->spendingRefreshTokens(),
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
        if (! $spent) {
            return false;
        }
        if ($authorization->scopes->has(Scope::offlineAccess())) {
            return true;
        }

        return $this->refreshTokenWithoutOfflineAccess && ! $authorization->client->registration->isPublic();
    }

    /**
     * RFC 6749 §4.1.2: every token issued from the code is revoked.
     */
    private function replayed(AuthorizationCode $code, Client $presentedBy, RequestContext $context, DateTimeImmutable $now): void
    {
        $code->revoke($now);
        $this->codes->save($code);
        $revoked = $this->refreshTokens->revokeByAuthorizationCode($code->codeHash, $now);
        if ($this->accessTokens instanceof CanRevokeAccessTokensByGrantInterface) {
            $this->accessTokens->revokeByGrant($code->grantId);
        }
        $this->events->dispatch(AuthorizationCodeReplayed::of($now, $code, $presentedBy, $revoked, $context));
    }
}
