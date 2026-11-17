<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Administration;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;

/**
 * The consents in force of a person of the tenant, as an administrator reads them through the administration API: what
 * `beffroi:user:applications` prints.
 */
final readonly class ReadConsents
{
    /**
     * @param list<Consent> $consents the last granted to each client
     */
    public function __construct(
        public User $user,
        public array $consents,
    ) {
    }
}
