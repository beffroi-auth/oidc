<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Domain\Token\InspectedAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use SensitiveParameter;

/**
 * What the provider's own resources ask of an access token (architecture §4.6, §4.7, §4.12): verified,
 * descending from a session that has not ended and from a grant still alive, naming a user still served.
 *
 * The questions are asked here, in one way for both shapes of token: what an "at+jwt" carries as "sid" and
 * "grant_id" is what the record of an opaque token carries as a row, and a resource of the provider is the
 * one reader able to resolve either. A resource server that holds the token and the published keys and
 * nothing else cannot ask them, which is what verifying offline means (RFC 9068 §4); the provider never
 * has that excuse.
 *
 * Each question is asked of the tokens that can answer it. A token somebody signed in for answers for its
 * session and for its user; a token a client holds for itself descends from no sign-in and names nobody
 * (RFC 6749 §4.4), so neither question is asked of it and neither is answered in its favour by default.
 * What the token says it descends from is what decides, never the name of the grant that issued it.
 */
final readonly class AccessTokenInspector
{
    public function __construct(
        private AccessTokenVerifier $tokens,
        private AuthenticationSessionRepositoryInterface $sessions,
        private AuthorizationCodeRepositoryInterface $grants,
        private UserRepositoryInterface $users,
    ) {
    }

    /**
     * @throws InvalidTokenException
     */
    public function inspect(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): InspectedAccessToken
    {
        $token = $this->tokens->verify($tenant, $accessToken, $now);
        $signIn = $token->signIn;
        if ($signIn === null) {
            return new InspectedAccessToken($token, null);
        }
        $session = $this->sessions->find($signIn->sessionId);
        if ($session === null || $session->hasEnded()) {
            throw new InvalidTokenException('The access token descends from a session this provider ended.');
        }
        $grant = $this->grants->findByGrantId($token->grantId);
        if ($grant === null || $grant->isRevoked()) {
            throw new InvalidTokenException('The access token descends from a grant this provider revoked.');
        }
        $user = $this->users->findBySubject($tenant, $token->subject);
        if ($user === null || ! $user->isEnabled()) {
            throw new InvalidTokenException('The access token names a user this provider no longer serves.');
        }

        return new InspectedAccessToken($token, $user);
    }
}
