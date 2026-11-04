<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * Held as is, not hashed: client_secret_jwt computes a MAC with it (OIDC Core §9).
 */
final readonly class SharedClientSecret implements ClientSecretInterface
{
    public function __construct(
        #[SensitiveParameter]
        public string $value,
    ) {
        if ($value === '') {
            throw new InvalidArgumentException('A shared client secret is not empty.');
        }
    }
}
