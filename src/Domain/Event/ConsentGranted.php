<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

final readonly class ConsentGranted implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'consent.granted';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $consentId,
        public string $clientId,
        public Subject $subject,
        public Scopes $scopes,
        public ?AuthorizationDetails $authorizationDetails,
        public ClaimNames $claims,
        public ?Uuid $supersedes,
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
