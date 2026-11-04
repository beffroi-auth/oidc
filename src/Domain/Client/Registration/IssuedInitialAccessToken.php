<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use SensitiveParameter;

final readonly class IssuedInitialAccessToken
{
    public function __construct(
        public InitialAccessToken $token,
        #[SensitiveParameter]
        public string $value,
    ) {
    }
}
