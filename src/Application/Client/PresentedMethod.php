<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;

/**
 * A method a request presents, and the client it names under it (RFC 6749 §2.3): what a method answers
 * when it reads a request and finds what it needs there. The two travel together because neither is
 * worth anything without the other, and what the authenticator then asks of the pair it asks by name.
 */
final readonly class PresentedMethod
{
    public function __construct(
        public AuthenticationMethodInterface $method,
        public string $clientId,
    ) {
    }

    /**
     * Whether what was presented proves the client, or only names it: a public client names itself and
     * carries no credential (RFC 6749 §2.1).
     */
    public function authenticatesClient(): bool
    {
        return $this->method->authenticatesClient();
    }

    /**
     * Whether the credential read is the certificate of the connection (RFC 8705 §2), which the client
     * presented because the listener asked and not because the request chose it.
     */
    public function bindsACertificate(): bool
    {
        return $this->method instanceof CertificateBindingMethodInterface;
    }

    /**
     * What of the request was read: two methods reading the same thing are one mechanism of
     * RFC 6749 §2.3, whichever of them a client registered.
     *
     * @return non-empty-string
     */
    public function mechanism(): string
    {
        return $this->method->mechanism();
    }

    /**
     * @return non-empty-string
     */
    public function name(): string
    {
        return $this->method->name();
    }
}
