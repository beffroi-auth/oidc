<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Exception\LogicException;
use function sprintf;

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
        return 'the certificate of the connection';
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->certificate === null ? null : $request->clientId();
    }

    /**
     * The tokens of the request are bound to the certificate it proved (§3.1). The authenticator picked
     * this method because that certificate was there, so its absence at this point is a fault of this
     * module.
     *
     * @throws LogicException when the request carries none
     */
    public function confirmationOf(ClientAuthenticationRequest $request): CertificateConfirmation
    {
        return CertificateConfirmation::ofCertificate(
            $request->certificate ?? throw new LogicException(sprintf(
                'A request that authenticated a client with %s carries a certificate.',
                $this->name(),
            )),
        );
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
