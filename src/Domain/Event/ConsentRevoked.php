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

final readonly class ConsentRevoked implements ConcernsAClientInterface, ConcernsAPersonInterface, NamesItsAuthorInterface
{
    public const string NAME = 'consent.revoked';

    /**
     * @param list<Uuid> $revokedGrants
     * @param list<string> $revokedRefreshTokenHashes
     * @param list<string> $revokedAccessTokenHashes
     * @param Subject|null $administrator the administrator of the tenant who took it back, by the subject of their account; null when the person or the operator of the instance did
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
