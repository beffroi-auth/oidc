<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_any;
use DateTimeImmutable;
use function explode;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 6749 §6, RFC 9700 §4.13 (architecture §4.5): the token is known, issued to this client, not
 * revoked, not expired, and not yet rotated; the scope asked for, if any, is within the one granted,
 * otherwise "invalid_scope". The token is rotated on every use: the one presented is marked, its
 * successor is issued in the same family with the same scopes (§6: "the refresh token scope MUST be
 * identical to that of the refresh token included by the client in the request"). An ID token is
 * reissued when "openid" is among the scopes of the response, without nonce (OIDC Core §12.2).
 *
 * A rotated token presented again is a reuse (RFC 9700 §4.13.2): the whole family is revoked and the
 * grant fails, because the provider cannot tell the legitimate client from the one holding a copy.
 *
 * The session the token descends from may have expired: offline access is what a refresh token is for.
 * It must not have been ended: a logout revokes the tokens of the session (architecture §4.9), and a
 * token that outlived that revocation is refused here rather than honoured.
 */
final readonly class RefreshTokenGrant implements GrantInterface
{
    private const string INVALID = 'The refresh token is invalid.';

    public function __construct(
        private RefreshTokenRepositoryInterface $refreshTokens,
        private TokenIssuer $issuer,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    public function grantType(): GrantType
    {
        return GrantType::RefreshToken;
    }

    public function grant(Client $client, TokenRequest $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $value = $request->required('refresh_token');
        $scopes = self::scopes($request->optional('scope'));

        $token = $this->refreshTokens->findByTokenHash(RefreshToken::hash($value));
        if ($token === null || ! $token->client->equals($client) || $token->isRevoked()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isRotated()) {
            $this->reused($token, $context, $now);

            throw new InvalidGrantException(self::INVALID);
        }
        if ($token->isExpired($now) || $token->session->hasEnded()) {
            throw new InvalidGrantException(self::INVALID);
        }
        if ($scopes !== null && ! $token->covers($scopes)) {
            throw new InvalidScopeException('The requested scope exceeds the scope granted to the refresh token (RFC 6749 section 6).');
        }

        $token->rotate($now);
        $this->refreshTokens->save($token);
        $authorization = GrantedAuthorization::fromRefreshToken($token, $scopes);
        $successor = $this->issuer->refreshToken($token->family, $authorization, $now);
        $this->events->dispatch(new RefreshTokenRotated($token, $successor->token, $context));

        return $this->issuer->issue($authorization, $successor, $context, $now);
    }

    /**
     * RFC 6749 §3.3: scope = scope-token *( SP scope-token ), read without repeats.
     *
     * @return non-empty-list<Scope>|null null when the client did not narrow the scope
     */
    private static function scopes(?string $scope): ?array
    {
        if ($scope === null) {
            return null;
        }
        $scopes = [];
        foreach (explode(' ', $scope) as $token) {
            try {
                $candidate = new Scope($token);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidScopeException('The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).', previous: $exception);
            }
            if (! array_any($scopes, static fn (Scope $kept): bool => $kept->equals($candidate))) {
                $scopes[] = $candidate;
            }
        }

        /** @var non-empty-list<Scope> $scopes the first token was either refused or kept */
        return $scopes;
    }

    /**
     * RFC 9700 §4.13.2: the family is revoked, the presented token included, and the detection is announced.
     */
    private function reused(RefreshToken $presented, RequestContext $context, DateTimeImmutable $now): void
    {
        $revoked = [];
        foreach ($this->refreshTokens->findByFamily($presented->family->id) as $token) {
            if ($token->isRevoked()) {
                continue;
            }
            $token->revoke($now);
            $this->refreshTokens->save($token);
            $revoked[] = $token;
        }
        $this->events->dispatch(new RefreshTokenReuseDetected($now, $presented, $revoked, $context));
    }
}
