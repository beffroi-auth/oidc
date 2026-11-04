<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class RegisteredClientDeleted implements ConcernsAClientInterface
{
    public const string NAME = 'registered_client.deleted';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}
