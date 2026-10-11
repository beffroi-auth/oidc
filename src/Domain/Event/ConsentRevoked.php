<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A user took back what they had agreed to let a client obtain, from the page of their account or through
 * the console, and what had been issued under it went with it (architecture §4.3).
 */
final readonly class ConsentRevoked implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'consent.revoked';

    /**
     * @param Subject $subject the person who took it back, by the subject their account carries (issue #588)
     * @param list<Uuid> $revokedGrants the grants the tokens of that client descended from
     * @param list<string> $revokedRefreshTokenHashes see RevokedTokenHashes::of()
     * @param list<string> $revokedAccessTokenHashes see RevokedTokenHashes::of()
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
