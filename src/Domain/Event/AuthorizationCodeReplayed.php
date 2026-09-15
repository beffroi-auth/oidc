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
 * An authorization code was presented a second time (RFC 6749 §4.1.2): the tokens issued from it are
 * revoked, whoever presented it. Worth a look in the audit trail: a code seen twice was seen by two
 * parties, or by one that lost the answer.
 */
final readonly class AuthorizationCodeReplayed implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param Client $presentedBy the authenticated client that presented the code again, not necessarily the one it was issued to
     * @param list<RefreshToken> $revoked the refresh tokens descending from the code, revoked by this detection
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
