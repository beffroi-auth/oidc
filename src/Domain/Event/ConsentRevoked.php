<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class ConsentRevoked implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'consent.revoked';

    /**
     * @param list<Uuid> $revokedGrants
     * @param list<string> $revokedRefreshTokenHashes
     * @param list<string> $revokedAccessTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $consentId,
        public string $clientId,
        public Subject $subject,
        public array $revokedGrants,
        public array $revokedRefreshTokenHashes,
        public array $revokedAccessTokenHashes,
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
