<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class AuthorizationCodeReplayed implements ConcernsAPersonInterface
{
    public const string NAME = 'authorization_code.replayed';

    /**
     * @param list<string> $revokedTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $codeHash,
        public Subject $subject,
        public string $issuedTo,
        public string $presentedBy,
        public array $revokedTokenHashes,
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
