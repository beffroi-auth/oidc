<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * A refresh token that had already been rotated was presented again (RFC 9700 §4.13.2): either the
 * legitimate client lost its successor, or someone else holds a copy. The provider cannot tell, so the
 * whole family is revoked and the user will log in again. Worth a look in the audit trail.
 */
final readonly class RefreshTokenReuseDetected implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param RefreshToken $presented the rotated token that was presented again
     * @param list<RefreshToken> $revoked the tokens of the family revoked by this detection
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
