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
 * RFC 6749 §6, RFC 9700 §4.13 (architecture §4.5): the token is rotated on every use, its successor in
 * the same family with the same scopes; a rotated token presented again revokes the family (§4.13.2).
 * The session may have expired, not have been ended (architecture §4.9).
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
     * RFC 6749 §3.3, without repeats.
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

        /** @var non-empty-list<Scope> $scopes */
        return $scopes;
    }

    /**
     * RFC 9700 §4.13.2.
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
