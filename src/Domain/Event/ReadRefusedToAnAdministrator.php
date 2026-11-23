<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * An administrator asked the administration API for persons past the budget of their reads (decision 0059): the
 * request delivered nobody, and the act is the administrator's, in their own journal, naming them as its author.
 */
final readonly class ReadRefusedToAnAdministrator implements ConcernsAClientInterface, ConcernsAPersonInterface, NamesItsAuthorInterface
{
    public const string NAME = 'administration.read_refused';

    /**
     * @param string  $clientId      the client the administrator acts through, the screen or the TUI
     * @param Subject $administrator the administrator refused, by the subject of their own account
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $administrator,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->administrator;
    }

    public function author(): Subject
    {
        return $this->administrator;
    }
}
