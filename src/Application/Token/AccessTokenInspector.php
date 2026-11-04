<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Token\InspectedAccessToken;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use SensitiveParameter;

/**
 * Verifies an access token and that its session has not ended, its grant is alive and its person is still served.
 */
final readonly class AccessTokenInspector
{
    public function __construct(
        private AccessTokenVerifier $tokens,
        private AuthenticationSessionRepositoryInterface $sessions,
        private RecordedGrantsInterface $grants,
        private PersonOfAnAccessToken $persons,
    ) {
    }

    /**
     * @throws InvalidTokenException
     */
    public function inspect(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): InspectedAccessToken
    {
        $token = $this->tokens->verify($tenant, $accessToken, $now);
        $signIn = $token->signIn;
        if ($signIn !== null) {
            $session = $this->sessions->find($signIn->sessionId);
            if ($session === null || $session->hasEnded()) {
                throw new InvalidTokenException('The access token descends from a session this provider ended.');
            }
            $grant = $this->grants->findByGrantId($token->grantId);
            if ($grant === null || $grant->isRevoked()) {
                throw new InvalidTokenException('The access token descends from a grant this provider revoked.');
            }
        }
        if (! $token->namesAPerson()) {
            return new InspectedAccessToken($token, null);
        }
        $user = $this->persons->of($token);
        if ($user === null || ! $user->isEnabled()) {
            throw new InvalidTokenException('The access token names a user this provider no longer serves.');
        }

        return new InspectedAccessToken($token, $user);
    }
}
