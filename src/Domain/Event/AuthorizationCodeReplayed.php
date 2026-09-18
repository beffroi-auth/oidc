<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * An authorization code was presented a second time (RFC 6749 §4.1.2); the tokens issued from it are revoked.
 */
final readonly class AuthorizationCodeReplayed implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param Client $presentedBy not necessarily the one the code was issued to
     * @param list<RefreshToken> $revoked
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public AuthorizationCode $code,
        public Client $presentedBy,
        public array $revoked,
        public RequestContext $context,
    ) {
        $this->tenant = $code->client->tenant;
    }
}
