<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * A refresh token was presented and replaced by its successor in the same family (RFC 6749 §6,
 * RFC 9700 §4.13.2).
 */
final readonly class RefreshTokenRotated implements DomainEventInterface
{
    public DateTimeImmutable $occurredAt;

    public Tenant $tenant;

    public function __construct(
        public RefreshToken $previous,
        public RefreshToken $next,
        public RequestContext $context,
    ) {
        $this->occurredAt = $next->issuedAt;
        $this->tenant = $next->client->tenant;
    }
}
