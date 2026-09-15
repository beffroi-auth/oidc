<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * What a protected resource of the provider knows once an access token has been verified (RFC 9068 §4):
 * the client it was issued to, the subject it names, the scopes it carries (§2.2.3), the claims the
 * client asked for by name from UserInfo ("userinfo_claims", architecture §4.6) and when it expires.
 * The user behind the subject is not here: the resource looks them up, and answers for what it finds.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param list<Scope> $scopes
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5, in the order the client gave them
     */
    public function __construct(
        public Client $client,
        public Subject $subject,
        public array $scopes,
        public array $userinfoClaims,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}
