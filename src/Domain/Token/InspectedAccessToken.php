<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\User;

final readonly class InspectedAccessToken
{
    public function __construct(
        public VerifiedAccessToken $token,
        public ?User $user,
    ) {
    }
}
