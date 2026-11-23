<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class LogoutTokenGivenUp implements ConcernsAClientInterface, ConcernsAPersonInterface, NamesItsAuthorInterface
{
    public const string NAME = 'logout_token.given_up';

    /**
     * @param Subject|null $administrator the administrator of the tenant who ended the session, by the subject of their account
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public string $clientId,
        public Subject $subject,
        public Uuid $sessionId,
        public string $reason,
        public ?Subject $administrator = null,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->subject;
    }

    public function author(): ?Subject
    {
        return $this->administrator;
    }
}
