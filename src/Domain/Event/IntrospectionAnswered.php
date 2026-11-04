<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * RFC 7662 §2.2
 *
 * Never raised for an inactive token: a caller would reach the journal of a person whose token it does not hold.
 */
final readonly class IntrospectionAnswered implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'introspection.answered';

    /**
     * @param Subject $subject the subject of the person's account
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
