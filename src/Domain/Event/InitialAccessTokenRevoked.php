<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * An act of the tenant and of no person: the clients the token registered stay.
 */
final readonly class InitialAccessTokenRevoked implements NamesItsAuthorInterface
{
    public const string NAME = 'initial_access_token.revoked';

    /**
     * @param Subject|null $administrator the administrator of the tenant who revoked it, by the subject of their account; null when the operator of the instance did
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $tokenId,
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
