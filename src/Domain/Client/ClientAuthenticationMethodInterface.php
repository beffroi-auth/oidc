<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * One way a client proves who it is at an endpoint that authenticates it (RFC 6749 §2.3, OIDC Core §9).
 * One class per method, wired into the provider: what the discovery document announces and what the
 * endpoints take read that one wired list (issue #98), and a method the provider gains is a class added
 * to the wiring, never a case added to an enumeration.
 */
interface ClientAuthenticationMethodInterface
{
    /**
     * The name of "token_endpoint_auth_methods_supported" (OIDC Discovery §3), which is also the name a
     * client registers.
     *
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * RFC 6749 §2.1: false for the method of a public client, which names itself and proves nothing. An
     * endpoint that serves an authenticated caller only (RFC 7662 §2.1) reads this.
     */
    public function authenticatesClient(): bool;
}
