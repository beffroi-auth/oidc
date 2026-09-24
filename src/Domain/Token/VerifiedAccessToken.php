<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified access token says, whatever its shape (RFC 9068 §4, architecture §4.6). Neither the
 * user nor the grant is looked up here.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param list<string> $userinfoClaims the names of OIDC Core §5.5
     * @param ConfirmationInterface|null $confirmation what the token is bound to (RFC 8705 §3, RFC 9449 §6.1), null for a bearer token
     */
    public function __construct(
        public Client $client,
        public Subject $subject,
        public Uuid $sessionId,
        public Uuid $grantId,
        public ?Scopes $scopes,
        public array $userinfoClaims,
        public AuthenticationSnapshot $authentication,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }
}
