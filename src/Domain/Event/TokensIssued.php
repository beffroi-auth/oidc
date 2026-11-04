<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Never carries the value of a token.
 */
final readonly class TokensIssued implements ClientInUseInterface, ConcernsAPersonInterface
{
    public const string NAME = 'tokens.issued';

    /**
     * @param Subject|null $subject the subject of the person's account, never the "sub" the client was answered
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public string $clientId,
        public ?Subject $subject,
        public ?Uuid $sessionId,
        public Scopes $grantedScopes,
        public DateTimeImmutable $accessTokenExpiresAt,
        public bool $idTokenIssued,
        public ?ConfirmationInterface $confirmation,
        public ?string $refreshTokenHash,
        public ?ClaimsRequest $claimsRequest,
        public ?AuthorizationDetails $authorizationDetails,
        public string $tokenShape,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): ?Subject
    {
        return $this->subject;
    }
}
