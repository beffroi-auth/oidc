<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * A user agreed, on the consent page, to let a client obtain the scopes of a request, whatever that request
 * asked for beyond them (RFC 9396 §2) and the claims it asked for by name (OIDC Core §5.5).
 */
final readonly class ConsentGranted implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'consent.granted';

    /**
     * @param Subject $subject the person who agreed, by the subject their account carries (issue #588)
     * @param AuthorizationDetails|null $authorizationDetails what the consent carries beyond its scopes, null when it carries none
     * @param ClaimNames $claims the claims the consent carries by name, none when it carries none
     * @param Uuid|null $supersedes the consent this one takes over from, null when the user had granted nothing yet
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $consentId,
        public string $clientId,
        public Subject $subject,
        public Scopes $scopes,
        public ?AuthorizationDetails $authorizationDetails,
        public ClaimNames $claims,
        public ?Uuid $supersedes,
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
