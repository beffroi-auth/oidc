<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\AccessTokenVerifierInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use SensitiveParameter;

/**
 * Reads back an opaque access token (architecture §4.6), the counterpart of OpaqueAccessTokenIssuer: the
 * record kept under the digest of the value, which is the only thing that says what the token is for. A
 * token of this shape is a reference the provider holds, so it can be taken back (RFC 7009 §2.1).
 */
final readonly class OpaqueAccessTokenVerifier implements AccessTokenVerifierInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $storedTokens,
        private SubjectIdentifierResolverInterface $subjects,
    ) {
    }

    /**
     * The shape this provider draws an opaque token in, and nothing else: a value of another shape was
     * not issued here, whatever a store might answer for it.
     */
    public function recognises(#[SensitiveParameter] string $accessToken): bool
    {
        return DrawnSecret::isValue($accessToken);
    }

    public function expiresOnItsOwn(): bool
    {
        return false;
    }

    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        $token = $this->storedTokens->find($accessToken);
        if ($token === null || ! $token->tenant->equals($tenant)) {
            throw InvalidTokenException::notIssuedHere();
        }
        if ($token->isExpired($now)) {
            throw InvalidTokenException::expired();
        }
        $requested = $token->claimsRequest === null ? [] : array_keys($token->claimsRequest->userinfo);

        return new VerifiedAccessToken(
            $token->client,
            $this->subjects->resolve($token->session->user, $token->client),
            $token->session->id,
            $token->grantId,
            $token->scopes,
            $requested,
            $token->authentication,
            $token->issuedAt,
            $token->expiresAt,
            $token->confirmation,
        );
    }
}
