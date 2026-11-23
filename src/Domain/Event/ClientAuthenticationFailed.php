<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\SaysWhyItWasRefusedInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class ClientAuthenticationFailed implements MayConcernAClientInterface, SaysWhyItWasRefusedInterface
{
    public const string NAME = 'client_authentication.failed';

    /**
     * @param string|null $clientId the client the request named, when the tenant holds it: an identifier anybody may present names no client otherwise (decision 0062)
     * @param string|null $method   the method of client authentication the request presented, by the name this provider gives it
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public ClientAuthenticationFailureReason $reason,
        public ?string $clientId,
        public ?string $method,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function refusalReason(): string
    {
        return $this->reason->value;
    }

    public function refusedMethod(): ?string
    {
        return $this->method;
    }
}
