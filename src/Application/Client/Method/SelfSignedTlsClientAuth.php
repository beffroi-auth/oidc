<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Beffroi\Oidc\Exception\ClientNotAuthenticatedHereException;

/**
 * RFC 8705 §2.2, RFC 7517 §4.7, §4.9
 *
 * The certificate itself is compared, not its key: one reissued on the same key is another certificate.
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
