<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * OIDC Core §5.3
 */
final readonly class UserInfoAnswered implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'userinfo.answered';

    /**
     * @param Subject $subject the subject of the person's account, never the "sub" answered
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
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
