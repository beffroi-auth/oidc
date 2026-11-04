<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Symfony\Component\Uid\Uuid;

final readonly class LogoutTokenIssued implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'logout_token.issued';

    /**
     * @param Subject $subject the subject of the person's account, never the "sub" the token names
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
        public ClientUri $logoutUri,
        public Uuid $sessionId,
        public string $token,
        public RequestContext $context,
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
}
