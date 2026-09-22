<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ResponseEncryption;
use Heidi\Oidc\Exception\RuntimeException;

interface JweEncrypterInterface
{
    /**
     * A compact JWE addressed to one public key (RFC 7516 §7.1). No key of the tenant is involved: what
     * is encrypted here is for the client to open, and only the client holds the private half.
     *
     * @param array<string, mixed> $recipient the public JWK the JWE is addressed to
     * @param array<string, mixed> $protectedHeader what the caller adds; "alg", "enc" and the "kid" of the recipient are written here
     *
     * @throws RuntimeException when the key cannot receive a JWE under that algorithm, which a
     *                          registration checked at boot has already made impossible
     */
    public function encrypt(array $recipient, ResponseEncryption $encryption, string $payload, array $protectedHeader = []): string;
}
