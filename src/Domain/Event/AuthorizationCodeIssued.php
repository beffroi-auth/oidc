<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * An authorization code left for a client; the record carries the hash only.
 */
final readonly class AuthorizationCodeIssued implements DomainEventInterface
{
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Uuid $grantId,
        public Uuid $sessionId,
        public string $codeHash,
        public Scopes $scopes,
        public DateTimeImmutable $expiresAt,
        public RequestContext $context,
    ) {
    }

    public static function of(AuthorizationCode $code, RequestContext $context): self
    {
        return new self(
            $code->issuedAt,
            $code->tenant,
            $code->clientId,
            $code->grantId,
            $code->session->id,
            $code->codeHash,
            $code->scopes,
            $code->expiresAt,
            $context,
        );
    }
}
