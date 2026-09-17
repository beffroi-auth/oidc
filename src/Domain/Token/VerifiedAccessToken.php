<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a protected resource of the provider knows once an access token has been verified, whatever its
 * shape (RFC 9068 §4 for the JWT, the record of the provider for the opaque one, architecture §4.6): the
 * client it was issued to, the subject it names, the session and the grant it descends from ("sid",
 * "grant_id"), the scopes it carries (§2.2.3), the claims the client asked for by name from UserInfo
 * ("userinfo_claims"), the authentication it stands on ("auth_time", "amr", "acr", §2.2.1) and its two
 * dates. The user behind the subject is not here: the resource looks them up, and answers for what it
 * finds. Whether the grant is still alive is a question for the provider's own resources: nothing here
 * reads a grant, a resource server holding only a JWT and the keys cannot either.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param list<Scope> $scopes
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5, in the order the client gave them
     * @param list<string> $authenticationMethods the "amr" values
     * @param string $authenticationContextClass the "acr" value
     */
    public function __construct(
        public Client $client,
        public Subject $subject,
        public Uuid $sessionId,
        public Uuid $grantId,
        public array $scopes,
        public array $userinfoClaims,
        public DateTimeImmutable $authenticatedAt,
        public array $authenticationMethods,
        public string $authenticationContextClass,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}
