<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Domain\Token\InspectedAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use SensitiveParameter;

/**
 * What the provider's own resources ask of an access token before honouring it (architecture §4.6, §4.7,
 * §4.12), whatever its shape: verified as one of the provider's, descending from a grant that is still
 * alive, naming a user the provider still serves. A resource server that holds only a JWT and the keys
 * cannot ask the last two; the provider knows where its grants and its users live, and RFC 6749 §4.1.2
 * asks the tokens of a replayed code to stop working. UserInfo answers with the user found here, the
 * introspection endpoint (RFC 7662) tells a resource server what it found. Nothing is written.
 */
final readonly class AccessTokenInspector
{
    public function __construct(
        private AccessTokenVerifier $tokens,
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
