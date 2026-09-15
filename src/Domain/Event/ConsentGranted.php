<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Consent\Consent;

/**
 * A user agreed, on the consent page, to let a client obtain the scopes of a request.
 */
final readonly class ConsentGranted implements DomainEventInterface
{
    public DateTimeImmutable $occurredAt;

    public Tenant $tenant;

    /**
     * @param Consent|null $supersedes the consent in force until this one, if any
     */
    public function __construct(
        public Consent $consent,
        public ?Consent $supersedes,
        public RequestContext $context,
    ) {
        $this->occurredAt = $consent->grantedAt;
        $this->tenant = $consent->tenant;
    }
}
