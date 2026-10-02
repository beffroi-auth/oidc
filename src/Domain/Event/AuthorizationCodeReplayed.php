<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * An authorization code was presented a second time (RFC 6749 §4.1.2); the tokens issued from it are revoked.
 */
final readonly class AuthorizationCodeReplayed implements DomainEventInterface
{
    /**
     * @param string $presentedBy not necessarily the client the code was issued to
     * @param list<string> $revokedTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $codeHash,
        public string $issuedTo,
        public string $presentedBy,
        public array $revokedTokenHashes,
        public RequestContext $context,
    ) {
    }
}
