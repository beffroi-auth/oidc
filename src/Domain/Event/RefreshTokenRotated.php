<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A refresh token was presented and replaced by its successor in the same family (RFC 6749 §6,
 * RFC 9700 §4.13.2).
 */
final readonly class RefreshTokenRotated implements DomainEventInterface
{
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Uuid $familyId,
        public string $previousTokenHash,
        public string $nextTokenHash,
        public DateTimeImmutable $nextExpiresAt,
        public RequestContext $context,
    ) {
    }
}
