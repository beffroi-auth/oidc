<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;

final readonly class RequestedAuthentication
{
    public function __construct(
        public RequestedAuthenticationContext $context,
        public ?User $hinted,
    ) {
    }
}
