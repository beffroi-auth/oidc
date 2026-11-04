<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

final readonly class AuthorizationCodeIssued implements ClientInUseInterface, ConcernsAPersonInterface
{
    public const string NAME = 'authorization_code.issued';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
        public Uuid $grantId,
        public Uuid $sessionId,
        public string $codeHash,
        public Scopes $scopes,
        public DateTimeImmutable $expiresAt,
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
