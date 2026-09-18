<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * An authorization code left for a client; the record carries the hash only.
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
