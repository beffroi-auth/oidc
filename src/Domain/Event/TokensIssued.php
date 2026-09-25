<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The token endpoint answered a client: what was authorized and which tokens left, never their values.
 */
final readonly class TokensIssued implements DomainEventInterface
{
    /**
     * @param ConfirmationInterface|null $confirmation what the tokens that left are bound to, null for bearer ones (RFC 9449 §6, RFC 8705 §3)
     * @param string|null $refreshTokenHash the refresh token that left, by its hash, null when none did
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public string $clientId,
        public Uuid $sessionId,
        public Scopes $grantedScopes,
        public DateTimeImmutable $accessTokenExpiresAt,
        public bool $idTokenIssued,
        public ?ConfirmationInterface $confirmation,
        public ?string $refreshTokenHash,
        public RequestContext $context,
    ) {
    }
}
