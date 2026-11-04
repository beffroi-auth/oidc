<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientUri;
use SensitiveParameter;

/**
 * CIBA Core §10.2
 */
final readonly class BackchannelRequestAnswered implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'backchannel_request.answered';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public ?Subject $subject,
        public ClientUri $notificationEndpoint,
        #[SensitiveParameter]
        public string $authRequestId,
        #[SensitiveParameter]
        public string $notificationToken,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): ?Subject
    {
        return $this->subject;
    }
}
