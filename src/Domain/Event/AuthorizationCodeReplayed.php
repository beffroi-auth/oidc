<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * An authorization code was presented a second time (RFC 6749 §4.1.2); the tokens issued from it are revoked.
 */
final readonly class AuthorizationCodeReplayed implements ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'authorization_code.replayed';

    /**
     * @param Subject $subject the person the code was issued in the name of, by the subject their account carries: their tokens are the ones revoked, so the journal they read says why (issue #588)
     * @param string $presentedBy not necessarily the client the code was issued to
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
