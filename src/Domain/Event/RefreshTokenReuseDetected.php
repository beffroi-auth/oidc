<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\RefreshToken;
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

    /**
     * @param list<RefreshToken> $revoked
     */
    public static function of(DateTimeImmutable $occurredAt, RefreshToken $presented, array $revoked, RequestContext $context): self
    {
        return new self(
            $occurredAt,
            $presented->tenant,
            $presented->clientId,
            $presented->family->id,
            $presented->tokenHash,
            array_map(static fn (RefreshToken $token): string => $token->tokenHash, $revoked),
            $context,
        );
    }
}
