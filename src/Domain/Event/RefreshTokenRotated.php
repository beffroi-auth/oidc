<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\RefreshToken;
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

    public static function of(RefreshToken $previous, RefreshToken $next, RequestContext $context): self
    {
        return new self(
            $next->issuedAt,
            $next->tenant,
            $next->clientId,
            $next->family->id,
            $previous->tokenHash,
            $next->tokenHash,
            $next->expiresAt,
            $context,
        );
    }
}
