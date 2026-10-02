<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * A user agreed, on the consent page, to let a client obtain the scopes of a request and whatever that
 * request asked for beyond them (RFC 9396 §2).
 */
final readonly class ConsentGranted implements DomainEventInterface
{
    /**
     * @param AuthorizationDetails|null $authorizationDetails what the consent carries beyond its scopes, null when it carries none
     * @param Uuid|null $supersedes the consent this one takes over from, null when the user had granted nothing yet
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $consentId,
        public string $clientId,
        public Uuid $userId,
        public Scopes $scopes,
        public ?AuthorizationDetails $authorizationDetails,
        public ?Uuid $supersedes,
        public RequestContext $context,
    ) {
    }
}
