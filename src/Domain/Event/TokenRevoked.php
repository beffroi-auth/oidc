<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class TokenRevoked implements ConcernsAPersonInterface
{
    public const string NAME = 'token.revoked';

    public const string REFRESH_TOKEN = 'refresh_token';

    public const string ACCESS_TOKEN = 'access_token';

    /**
     * @param string $tokenType "refresh_token" or "access_token"
     * @param list<string> $revokedAccessTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $revokedBy,
        public ?Subject $subject,
        public string $tokenType,
        public string $tokenHash,
        public Uuid $grantId,
        public array $revokedAccessTokenHashes,
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
