<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;

/**
 * The signature of a JWT signed by the very key its header carries (RFC 7515 §4.1.3), which is what a
 * DPoP proof is (RFC 9449 §4.2): nobody vouches for the key, the proof only shows its holder signed
 * with it, and what the key is worth is said by the token that names its thumbprint.
 */
interface ProofKeyVerifierInterface
{
    /**
     * @param list<string> $algorithms the "alg" this provider verifies a proof with, asymmetric every
     *                                 one of them: a proof signed with a secret proves nothing about a
     *                                 key nobody shares
     *
     * @throws InvalidJwtException when the header carries no public key of one of those algorithms, when
     *                             it carries a private key, or when the signature does not verify
     *
     * @return string the JWK thumbprint of the key that signed, base64url of a SHA-256 (RFC 7638 §3),
     *                which is what binds a token to it
     */
    public function keyThatSigned(UnverifiedJwt $jwt, array $algorithms): string;
}
