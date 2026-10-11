<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * A client was answered the claims of a person (OIDC Core §5.3, issue #589). The other of the two reads
 * where a personal datum actually leaves this provider, and the one where what leaves is the person
 * themselves: the endpoint answers for a user and for nobody else, so every answer it gives is an act in
 * the name of somebody.
 *
 * It says that the read happened, who asked and about whom, and never which claims were served, which is
 * a row of its own (issue #590). The person is named by the subject their account carries and never by
 * the "sub" of the answer, which is the name that one client sees (§8.1).
 *
 * A request this endpoint refuses writes nothing: a token it does not honour, a binding the request did
 * not prove again, a token addressed elsewhere and a token with nobody behind it are refusals, and
 * nothing of anybody left.
 */
final readonly class UserInfoAnswered implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'userinfo.answered';

    /**
     * @param string $clientId the client the token was issued to, which is the one the claims were served to
     * @param Subject $subject the person whose claims were served, by the subject their account carries
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
