<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * A method whose client registers a shared secret (RFC 6749 §2.3.1, OIDC Core §9). The shape the secret
 * is kept in is the method's to name, because the method is what verifies against it: a hash for the
 * methods the secret is presented to, the secret itself for the one that computes a MAC with it.
 */
interface SecretBearingMethodInterface extends ClientAuthenticationMethodInterface
{
    /**
     * Whether a secret registered in that shape is one this method can verify against.
     */
    public function accepts(ClientSecretInterface $secret): bool;
}
