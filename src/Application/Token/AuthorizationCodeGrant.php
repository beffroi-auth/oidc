<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
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
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use function preg_match;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.1.3, RFC 7636 §4.6, OIDC Core §3.1.3 (architecture §4.5). Every failure is "invalid_grant"
 * with one description. The code is consumed by its first presentation (RFC 9700 §4.5); presented again,
 * the grant and every token descending from it are revoked (RFC 6749 §4.1.2).
 */
final readonly class AuthorizationCodeGrant implements GrantInterface
{
    /**
     * RFC 7636 §4.1: code-verifier = 43*128unreserved.
     */
    private const string CODE_VERIFIER_PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/';

    private const string INVALID = 'The authorization code is invalid.';

    /**
     * @param DateInterval $refreshTokenFamilyLifetime the absolute lifetime no rotation extends (architecture §4.6)
     */
    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private AccessTokenRepositoryInterface $accessTokens,
        private TokenIssuer $issuer,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private DateInterval $refreshTokenFamilyLifetime = new DateInterval('P90D'),
        private bool $refreshTokenWithoutOfflineAccess = true,
    ) {
    }

    public function grantType(): GrantType
    {
        return GrantType::AuthorizationCode;
    }

    public function grant(Client $client, TokenRequest $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $code = $request->required('code');
        $redirectUri = $request->required('redirect_uri');
        $codeVerifier = $request->optional('code_verifier');
        if ($codeVerifier !== null && preg_match(self::CODE_VERIFIER_PATTERN, $codeVerifier) !== 1) {
            throw new InvalidRequestException('The code_verifier parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.1).');
        }

        $record = $this->codes->findByCodeHash(AuthorizationCode::hash($code));
        if ($record === null) {
            throw new InvalidGrantException(self::INVALID);
        }
        // atomic: of the requests presenting this code at once, exactly one is the first
        if (! $this->codes->consume($record, $now)) {
            $this->replayed($record, $client, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }

        if (! $record->client->equals($client)
            || $record->isExpired($now)
            || ! $record->redirectUri->matches($redirectUri)
            || ! self::pkceSatisfied($record, $codeVerifier)
            || ! $record->session->isActive($now)) {
            throw new InvalidGrantException(self::INVALID);
        }

        $authorization = GrantedAuthorization::fromAuthorizationCode($record);
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

    private function refreshTokenDue(GrantedAuthorization $authorization): bool
    {
        if (! $authorization->client->allowsGrant(GrantType::RefreshToken)) {
            return false;
        }
        if ($authorization->hasScope(new Scope('offline_access'))) {
            return true;
        }

        return $this->refreshTokenWithoutOfflineAccess && ! $authorization->client->isPublic();
    }

    /**
     * RFC 6749 §4.1.2: every token issued from the code is revoked.
     */
    private function replayed(AuthorizationCode $code, Client $presentedBy, RequestContext $context, DateTimeImmutable $now): void
    {
        $code->revoke($now);
        $this->codes->save($code);
        $revoked = [];
        foreach ($this->refreshTokens->findByAuthorizationCode($code->codeHash) as $token) {
            if ($token->isRevoked()) {
                continue;
            }
            $token->revoke($now);
            $this->refreshTokens->save($token);
            $revoked[] = $token;
        }
        if ($this->accessTokens instanceof CanRevokeAccessTokensByGrantInterface) {
            $this->accessTokens->revokeByGrant($code->grantId);
        }
        $this->events->dispatch(new AuthorizationCodeReplayed($now, $code, $presentedBy, $revoked, $context));
    }
}
