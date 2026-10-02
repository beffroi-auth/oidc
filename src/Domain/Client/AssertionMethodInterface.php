<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * A method whose client proves itself with a JWT it signs (RFC 7523 §2.2, OIDC Core §9). What such an
 * assertion may be signed with is the method's to say; the discovery document announces the union of
 * what the wired methods say ("token_endpoint_auth_signing_alg_values_supported", OIDC Discovery §3),
 * never a list kept beside them.
 */
interface AssertionMethodInterface extends ClientAuthenticationMethodInterface
{
    /**
     * The "alg" an assertion of this method may carry, in the order they are wired.
     *
     * @return non-empty-list<non-empty-string>
     */
    public function assertionSigningAlgorithms(): array;
}
