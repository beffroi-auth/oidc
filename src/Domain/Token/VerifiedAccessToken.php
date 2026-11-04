<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified access token says, whatever its shape; neither its user nor its grant is looked up here.
 */
final readonly class VerifiedAccessToken
{
    /**
     * @param list<string> $userinfoClaims
     */
    public function __construct(
        public Client $client,
        public TokenAudience $audience,
        public Subject $subject,
        public Uuid $grantId,
        public ?Scopes $scopes,
        public ?TokenSignIn $signIn,
        public array $userinfoClaims,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
        public ?Actor $actor = null,
        public ?AuthorizationDetails $authorizationDetails = null,
        public ?Subject $person = null,
    ) {
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
    }

    public function namesAPerson(): bool
    {
        return $this->signIn !== null || $this->person !== null;
    }
}
