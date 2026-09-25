<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Heidi\Oidc\Exception\ClientNotAuthenticatedHereException;

/**
 * "self_signed_tls_client_auth" (RFC 8705 §2.2): the client presents a certificate it signed itself, and
 * the provider authenticates it when that certificate is one of those the client publishes in its JWK
 * Set, in the "x5c" of a key (RFC 7517 §4.7) or by the thumbprint of §4.9.
 *
 * There is no chain and no trust store: what is trusted is what the client published, exactly as for the
 * keys of "private_key_jwt". The certificate itself is compared and not the key inside it, because a
 * certificate reissued on the same key is another certificate: §2.2 authenticates a certificate the
 * client registered, and §3.1 binds the tokens of that request to the thumbprint of that very one.
 *
 * A client that rotates its certificate publishes the new one before presenting it, which is the same
 * discipline a client that rotates a signing key follows; a set behind a "jwks_uri" is read back with
 * the guard time of ClientKeySetProvider.
 */
final readonly class SelfSignedTlsClientAuth extends CertificateMethod implements KeyBearingMethodInterface
{
    public function __construct(
        private ClientKeySetProvider $keys,
    ) {
    }

    public function name(): string
    {
        return 'self_signed_tls_client_auth';
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            throw new ClientNotAuthenticatedHereException($client, $this);
        }
        if (! $this->keys->keysAuthenticating($client, null, $this)->publishes($certificate)) {
            throw $this->unexpectedCertificate($client, 'the certificate presented is not one the client publishes');
        }
    }
}
