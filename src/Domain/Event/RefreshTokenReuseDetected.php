<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * A rotated refresh token was presented again (RFC 9700 §4.13.2); the whole family is revoked.
 */
final readonly class RefreshTokenReuseDetected implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param list<RefreshToken> $revoked
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public RefreshToken $presented,
        public array $revoked,
        public RequestContext $context,
    ) {
        $this->tenant = $presented->client->tenant;
    }
}
