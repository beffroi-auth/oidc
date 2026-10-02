<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Credential\PasswordHash;
use SensitiveParameter;

/**
 * The secret of a client that presents it (RFC 6749 §2.3.1): kept hashed, like a password, verified by
 * the hasher of the core and never readable back.
 */
final readonly class HashedClientSecret implements ClientSecretInterface
{
    public function __construct(
        #[SensitiveParameter]
        public PasswordHash $hash,
    ) {
    }
}
