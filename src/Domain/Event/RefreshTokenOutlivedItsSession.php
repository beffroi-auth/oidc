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
 * A refresh token still recorded active was presented for a session that has ended, and refused (architecture
 * §4.9, issue #741): a refresh in flight when the session ended saved it after the tokens of the session were
 * revoked. What revokes them is told again, dated by the end of the session and not by this presentation.
 */
final readonly class RefreshTokenOutlivedItsSession implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'refresh_token.outlived_its_session';

    /**
     * @param Subject $subject the person whose session the token descends from, by the subject their account carries
     * @param DateTimeImmutable $sessionEndedAt the instant the session ended, which dates the revocation
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
        public Uuid $sessionId,
        public DateTimeImmutable $sessionEndedAt,
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
