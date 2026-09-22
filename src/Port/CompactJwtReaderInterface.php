<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;

/**
 * Reads a compact JWT a client sent, and verifies nothing (RFC 7519 §7.2): the header names the
 * algorithm and the key, the claims name the sender. A provider has to read that much before it can know
 * which client and which key would verify it. It reads the assertion that authenticates a client (RFC
 * 7523 §2.2) and the request object that carries its request (RFC 9101 §4) the same way; nothing read
 * here is trusted until a verifier has spoken.
 */
interface CompactJwtReaderInterface
{
    /**
     * @throws InvalidJwtException when the string is not a compact JWS carrying a JSON object
     */
    public function read(string $jwt): UnverifiedJwt;
}
