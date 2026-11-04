<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * RFC 7515 §4.1.3, RFC 9449 §4.2
 */
interface ProofKeyVerifierInterface
{
    /**
     * @param list<string> $algorithms asymmetric, every one of them
     *
     * @throws InvalidJwtException when the header carries no public key of one of those algorithms, when it carries a
     *                             private key, or when the signature does not verify
     *
     * @return string the JWK thumbprint of the key that signed, base64url of a SHA-256 (RFC 7638 §3)
     */
    public function keyThatSigned(UnverifiedJwt $jwt, array $algorithms): string;
}
