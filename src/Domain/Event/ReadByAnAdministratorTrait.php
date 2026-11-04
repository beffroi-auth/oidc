<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * What every read of a person through the administration API of their tenant carries (decisions 0022 and 0038): when,
 * the person read and the administrator who read them, both by the subject their accounts carry, and the client the
 * administrator read them through. Each kind of read is an act of its own, which names itself.
 */
trait ReadByAnAdministratorTrait
{
    /**
     * @param string  $clientId the client the administrator acts through, the screen or the TUI
     * @param Subject $subject the person read, by the subject their account carries
     * @param Subject $administrator the administrator who read them, by the subject of their own account
     */
    public function __construct(
        public readonly DateTimeImmutable $occurredAt,
        public readonly Tenant $tenant,
        public readonly string $clientId,
        public readonly Subject $subject,
        public readonly Subject $administrator,
        public readonly RequestContext $context,
    ) {
    }

    public function subject(): Subject
    {
        return $this->subject;
    }

    public function author(): Subject
    {
        return $this->administrator;
    }
}
