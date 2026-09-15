<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * An authorization code left for a client. The record carries the hash only; the value is in the user
 * agent and nowhere else.
 */
final readonly class AuthorizationCodeIssued implements DomainEventInterface
{
    public DateTimeImmutable $occurredAt;

    public Tenant $tenant;

    public function __construct(
        public AuthorizationCode $code,
        public RequestContext $context,
    ) {
        $this->occurredAt = $code->issuedAt;
        $this->tenant = $code->client->tenant;
    }
}
