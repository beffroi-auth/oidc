<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\ClientSubject;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Domain\Token\StoredUserAccessToken;
use Heidi\Oidc\Domain\Token\TokenSignIn;
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
 *
 * The record says whether somebody signed in for the token: the one kept for a sign-in names the user of
 * its session in "sub" and the sign-in it descends from, the one kept for a client acting for itself names
 * that client and no sign-in (RFC 6749 §4.4, RFC 9068 §2.2).
 */
final readonly class OpaqueAccessTokenVerifier implements AccessTokenVerifierInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $storedTokens,
        private SubjectIdentifierResolverInterface $subjects,
    ) {
    }

    /**
     * The shape OpaqueAccessTokenIssuer writes, which a client registers by this name.
     */
    public function name(): string
    {
        return 'opaque';
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
        $signedIn = $token instanceof StoredUserAccessToken;

        return new VerifiedAccessToken(
            $token->client,
            $token->audience(),
            $this->subjectOf($token),
            $token->grantId,
            $token->scopes,
            $signedIn ? new TokenSignIn($token->session->id, $token->authentication) : null,
            $signedIn && $token->claimsRequest !== null ? array_keys($token->claimsRequest->userinfo) : [],
            $token->issuedAt,
            $token->expiresAt,
            $token->confirmation,
        );
    }

    /**
     * RFC 9068 §2.2: the pairwise subject of the user who signed in (OIDC Core §8), and the client itself
     * when nobody did (RFC 6749 §4.4); the same rule the self-contained shape writes into its own "sub".
     */
    private function subjectOf(StoredAccessToken $token): Subject
    {
        return $token instanceof StoredUserAccessToken
            ? $this->subjects->resolve($token->session->user, $token->client)
            : ClientSubject::of($token->client);
    }
}
