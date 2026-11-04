<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_keys;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\ClientSubject;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredSubjectAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\AccessTokenVerifierInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use SensitiveParameter;

final readonly class OpaqueAccessTokenVerifier implements AccessTokenVerifierInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $storedTokens,
        private SubjectIdentifierResolverInterface $subjects,
    ) {
    }

    public function name(): string
    {
        return 'opaque';
    }

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
            self::signInOf($token),
            $signedIn && $token->claimsRequest !== null ? array_keys($token->claimsRequest->userinfo) : [],
            $token->issuedAt,
            $token->expiresAt,
            $token->confirmation,
            $token instanceof StoredSubjectAccessToken ? $token->actor : null,
            $signedIn ? $token->authorizationDetails : null,
            $token->person(),
        );
    }

    /**
     * RFC 9068 §2.2
     */
    private function subjectOf(StoredAccessToken $token): Subject
    {
        if ($token instanceof StoredSubjectAccessToken) {
            return $token->subject;
        }

        return $token instanceof StoredUserAccessToken
            ? $this->subjects->resolve($token->session->user, $token->client)
            : ClientSubject::of($token->client);
    }

    /**
     * RFC 9068 §2.2.1
     */
    private static function signInOf(StoredAccessToken $token): ?TokenSignIn
    {
        if ($token instanceof StoredSubjectAccessToken) {
            return $token->signIn();
        }

        return $token instanceof StoredUserAccessToken ? new TokenSignIn($token->session->id, $token->authentication) : null;
    }
}
