<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\StoredAccessToken;

/**
 * A client gave a token back at the revocation endpoint (RFC 7009 §2.1).
 */
final readonly class TokenRevoked implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param list<StoredAccessToken> $accessTokens revoked along with a refresh token (§2.1)
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public RefreshToken|StoredAccessToken $token,
        public Client $revokedBy,
        public array $accessTokens,
        public RequestContext $context,
    ) {
        $this->tenant = $revokedBy->tenant;
    }
}
