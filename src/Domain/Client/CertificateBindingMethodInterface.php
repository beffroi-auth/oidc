<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * A method that proves the client holds the private key of a certificate, and whose access tokens are
 * therefore bound to that certificate (RFC 8705 §3). What the discovery document announces as
 * "tls_client_certificate_bound_access_tokens" is whether one of these is wired, never a flag kept
 * beside them; what the binding is made of is said in the module, by the method itself.
 */
interface CertificateBindingMethodInterface extends ClientAuthenticationMethodInterface
{
}
