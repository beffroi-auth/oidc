<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Credential\PasswordHash;
use SensitiveParameter;

final readonly class HashedClientSecret implements ClientSecretInterface
{
    public function __construct(
        #[SensitiveParameter]
        public PasswordHash $hash,
    ) {
    }
}
