<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The secret of a client that signs with it (OIDC Core §9, "client_secret_jwt"): the provider computes
 * the same MAC as the client, so it holds the secret and not a hash of it. That is the method's own
 * cost, and the reason FAPI 2.0 Security Profile §5.3.2.1 takes no shared secret at all: a deployment
 * that follows the profile does not wire the method, and then no client can register it.
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
