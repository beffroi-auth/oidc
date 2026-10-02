<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * An authorization code left for a client; the record carries the hash only.
 */
final readonly class AuthorizationCodeIssued implements ClientInUseInterface
{
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Uuid $grantId,
        public Uuid $sessionId,
        public string $codeHash,
        public Scopes $scopes,
        public DateTimeImmutable $expiresAt,
        public RequestContext $context,
    ) {
    }
}
