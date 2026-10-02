<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A rotated refresh token was presented again (RFC 9700 §4.13.2); the whole family is revoked.
 */
final readonly class RefreshTokenReuseDetected implements DomainEventInterface
{
    /**
     * @param list<string> $revokedTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Uuid $familyId,
        public string $presentedTokenHash,
        public array $revokedTokenHashes,
        public RequestContext $context,
    ) {
    }
}
