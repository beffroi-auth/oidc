<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;

/**
 * A method whose client is recognised by the certificate of its connection (RFC 8705 §2). The two of
 * them read the same thing of a request, which is what makes them one mechanism of RFC 6749 §2.3: the
 * client names itself in "client_id" and the certificate proves it, so a request without a certificate
 * presents neither and a request without "client_id" names nobody to look up. Both bind the tokens they
 * issue to that very certificate (§3.1), by the thumbprint of the one the request proved.
 *
 * What makes the certificate the client's is the one thing that differs, a value registered for it or a
 * certificate the client publishes, and it is the one thing a kind says for itself.
 */
abstract readonly class CertificateMethod implements ConfirmingMethodInterface
{
    public function mechanism(): string
    {
        return ClientAuthenticationRequest::CERTIFICATE;
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->clientIdBesideACertificate();
    }

    public function confirmationOf(ClientAuthenticationRequest $request): CertificateConfirmation
    {
        return CertificateConfirmation::ofCertificate($request->provenCertificate($this));
    }

    /**
     * A certificate is compared to what a registration says or to what a client published, and both are
     * public on either side: there is no secret here whose comparison has to be made constant. A kind
     * that does work before it can compare pays that work here.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }

    /**
     * The refusal of a certificate that is not this client's, whichever way the kind establishes it.
     */
    protected function unexpectedCertificate(Client $client, string $description): ClientAuthenticationFailure
    {
        return ClientAuthenticationFailure::refused(
            ClientAuthenticationFailureReason::UnexpectedCertificate,
            $client->registration->clientId,
            $this->name(),
            $description,
        );
    }
}
