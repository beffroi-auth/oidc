<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

/**
 * What a client registers to be recognised by the certificate it presents (RFC 8705 §2.1.2): exactly one
 * of the five values of that section, each one a class that knows the metadata name it is registered
 * under and how its own kind of name is compared. A kind the specification adds later is a class added
 * here; nothing enumerates them and nothing reads a class name.
 */
interface CertificateIdentityInterface
{
    /**
     * The name of the registration metadata this value is registered under (RFC 8705 §2.1.2), which is
     * also the key a configuration writes.
     *
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * Whether the certificate presented names this client, the whole of what "tls_client_auth" verifies
     * once the edge has proven the chain (RFC 8705 §2.1).
     */
    public function matches(CertificateSubject $subject): bool;
}
