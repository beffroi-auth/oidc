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
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use function preg_match;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.1.3, RFC 7636 §4.6, OIDC Core §3.1.3 (architecture §4.5): the code is known, not yet
 * presented, issued to this client and not expired; "redirect_uri" is the one of the authorization
 * request, byte for byte; the code verifier hashes to the challenge, compared in constant time; the
 * session the code was issued for is still active. Every failure is "invalid_grant" with one description:
 * which check failed is not for the caller.
 *
 * A code is consumed by its first presentation, before anything else is checked, so that a failed
 * attempt cannot be retried with another verifier. Presented a second time, by whichever client, the
 * code is a replay: every refresh token descending from it is revoked (RFC 6749 §4.1.2) and the grant
 * fails. The access tokens already issued are stateless and live ten minutes; they are the exposure
 * that decision 0006 accepts.
 *
 * A refresh token is issued when the client is registered for the refresh_token grant and either asked
 * for "offline_access" (OIDC Core §11) or is confidential and the tenant allows it without the scope
 * (architecture §4.5, §9: a choice made for the relying parties that expect one without asking, oidc_login
 * included). A public client without "offline_access" gets none.
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
     * @param bool $refreshTokenWithoutOfflineAccess whether a confidential client gets a refresh token without asking for "offline_access" (architecture §9)
     */
    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private RefreshTokenRepositoryInterface $refreshTokens,
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
        $codeVerifier = $request->required('code_verifier');
        if (preg_match(self::CODE_VERIFIER_PATTERN, $codeVerifier) !== 1) {
            throw new InvalidRequestException('The code_verifier parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.1).');
        }

        $record = $this->codes->findByCodeHash(AuthorizationCode::hash($code));
        if ($record === null) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($record->isUsed()) {
            $this->replayed($record, $client, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }
        $record->consume($now);
        $this->codes->save($record);

        if (! $record->client->equals($client)
            || $record->isExpired($now)
            || ! $record->redirectUri->matches($redirectUri)
            || ! $record->codeChallenge->verifies($codeVerifier)
            || ! $record->session->isActive($now)) {
            throw new InvalidGrantException(self::INVALID);
        }

        $authorization = GrantedAuthorization::fromAuthorizationCode($record);
        $refreshToken = null;
        if ($this->refreshTokenDue($authorization)) {
            $family = new RefreshTokenFamily(Uuid::v7(), $record->codeHash, $now, $now->add($this->refreshTokenFamilyLifetime));
            $refreshToken = $this->issuer->refreshToken($family, $authorization, $now);
        }

        return $this->issuer->issue($authorization, $refreshToken, $context, $now);
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
     * RFC 6749 §4.1.2: the request is denied and every token issued from the code is revoked.
     */
    private function replayed(AuthorizationCode $code, Client $presentedBy, RequestContext $context, DateTimeImmutable $now): void
    {
        $revoked = [];
        foreach ($this->refreshTokens->findByAuthorizationCode($code->codeHash) as $token) {
            if ($token->isRevoked()) {
                continue;
            }
            $token->revoke($now);
            $this->refreshTokens->save($token);
            $revoked[] = $token;
        }
        $this->events->dispatch(new AuthorizationCodeReplayed($now, $code, $presentedBy, $revoked, $context));
    }
}
