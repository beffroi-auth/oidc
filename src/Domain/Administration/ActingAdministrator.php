<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Administration;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * The administrator a request to the administration API of a tenant comes from (decision 0038), once the request was
 * found to be theirs: the person, the client they act through, and the session the token of the request descends
 * from. What the API reads and writes names them, an act of the journal first.
 */
final readonly class ActingAdministrator
{
    /**
     * @param string $clientId the client the token was issued to, the screen or the TUI the administrator uses
     * @param Uuid   $sessionId the session of the provider the token descends from
     */
    public function __construct(
        public Tenant $tenant,
        public User $user,
        public string $clientId,
        public Uuid $sessionId,
    ) {
    }
}
