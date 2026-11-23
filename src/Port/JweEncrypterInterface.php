<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ResponseEncryption;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;

interface JweEncrypterInterface
{
    /**
     * RFC 7516 §7.1
     *
     * @param array<string, mixed> $recipient the public JWK
     * @param array<string, mixed> $protectedHeader what the caller adds; "alg", "enc" and "kid" are written here
     *
     * @throws ClientKeysUnavailableException when the key cannot receive a JWE under that algorithm
     */
    public function encrypt(array $recipient, ResponseEncryption $encryption, string $payload, array $protectedHeader = []): string;
}
