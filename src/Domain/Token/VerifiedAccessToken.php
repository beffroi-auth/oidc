<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified access token says, whatever its shape (RFC 9068 §4, architecture §4.6). Neither the
 * user nor the grant is looked up here.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param list<Scope> $scopes
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5
     * @param Confirmation|null $confirmation what the token is bound to (RFC 8705 §3), null for a bearer token
     */
    public function __construct(
        public Client $client,
        public Subject $subject,
        public Uuid $sessionId,
        public Uuid $grantId,
        public array $scopes,
        public array $userinfoClaims,
        public AuthenticationSnapshot $authentication,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?Confirmation $confirmation = null,
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }

    /**
     * RFC 8705 §3: whether this token may be honoured by whoever made a request with that certificate. A
     * bearer token is honoured by whoever holds it; a bound one is honoured by the client that proved
     * the certificate again, and by nobody else, not even by the client it was issued to.
     */
    public function isHonouredWith(?ClientCertificate $certificate): bool
    {
        return $this->confirmation === null || $this->confirmation->isPresentedBy($certificate);
    }
}
