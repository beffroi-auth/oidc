<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * A resource server was told who a token names (RFC 7662 §2.2, issue #589). One of the two reads where a
 * personal datum actually leaves this provider, so it is an act and not a lookup: what the sealed columns
 * of a login open is read inside the provider and leaves nothing, where a client told who a token names
 * takes something out.
 *
 * It says that the read happened, who asked and about whom, and never what was handed over, which is a
 * row of its own (issue #590). The person is named by the subject their account carries, so the journal
 * of that person holds the line.
 *
 * **What describes nobody writes nothing.** An answer of `active: false` carries no other member (§2.2),
 * so there is nothing to say a read of; writing one would also let whoever asks after tokens they do not
 * hold reach the journal of somebody. A token a client holds for itself names a client and no person
 * (RFC 6749 §4.4), so a read of it hands no personal datum to anybody and is no act of this register
 * either.
 */
final readonly class IntrospectionAnswered implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'introspection.answered';

    /**
     * @param string $clientId the client that asked, which is the one the token was issued to (§2.2)
     * @param Subject $subject the person the token names, by the subject their account carries
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
