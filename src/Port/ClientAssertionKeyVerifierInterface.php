<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ClientAssertion;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Exception\InvalidClientAssertionException;

/**
 * Verifies the signature of a client assertion against the keys the client published (OIDC Core §9,
 * "private_key_jwt"). The key is chosen by the "kid" of the header among those keys alone, and by
 * nothing the token carries otherwise: "jwk", "jku" and "x5c" are ignored (RFC 8725 §3.10).
 */
interface ClientAssertionKeyVerifierInterface
{
    /**
     * @param non-empty-list<non-empty-string> $algorithms the "alg" the signature may carry
     *
     * @throws InvalidClientAssertionException when the algorithm is not one of those, the key is not
     *                                         published, or the signature does not verify
     */
    public function verify(ClientAssertion $assertion, ClientJwks $keys, array $algorithms): void;
}
