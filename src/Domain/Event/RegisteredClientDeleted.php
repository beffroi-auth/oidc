<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class RegisteredClientDeleted implements ConcernsAClientInterface, NamesItsAuthorInterface
{
    public const string NAME = 'registered_client.deleted';

    /**
     * @param Subject|null $administrator the administrator of the tenant who deleted it, by the subject of their account; null when the client itself, the retention of the tenant or the operator of the instance did
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public RequestContext $context,
        public ?Subject $administrator = null,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function author(): ?Subject
    {
        return $this->administrator;
    }
}
