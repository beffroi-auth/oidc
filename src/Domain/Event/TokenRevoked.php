<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A client gave a token back at the revocation endpoint (RFC 7009 §2.1). Which kind it gave back is
 * named by whoever revoked it, in the words of the "token_type_hint" of §2.1: the caller knows what it
 * revoked, so nothing here reads a class name to find out.
 */
final readonly class TokenRevoked implements DomainEventInterface
{
    public const string REFRESH_TOKEN = 'refresh_token';

    public const string ACCESS_TOKEN = 'access_token';

    /**
     * @param string $tokenType "refresh_token" or "access_token" (RFC 7009 §2.1)
     * @param list<string> $revokedAccessTokenHashes the access tokens revoked along with a refresh token (§2.1)
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $revokedBy,
        public string $tokenType,
        public string $tokenHash,
        public Uuid $grantId,
        public array $revokedAccessTokenHashes,
        public RequestContext $context,
    ) {
    }
}
