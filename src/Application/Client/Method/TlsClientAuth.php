<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\CertificateIdentityBearingMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\UnreadableCertificateException;
use Heidi\Oidc\Port\CertificateReaderInterface;
use function sprintf;

/**
 * "tls_client_auth" (RFC 8705 §2.1): the client presents a certificate issued by a certificate authority
 * the deployment trusts, and the provider recognises it by the one value of §2.1.2 it registered, read
 * out of the certificate and compared to what the registration says.
 *
 * What this method does not do is as important as what it does. It does not build a chain, does not look
 * at a validity period and does not ask a revocation list anything: the handshake did, at the edge,
 * before the request existed (docs/mtls-at-the-edge.md), because only the leaf reaches the provider and
 * a provider that judged a chain from the leaf alone would be judging nothing. The deployment that turns
 * this method on is the deployment that configures the authorities its listener accepts.
 */
final readonly class TlsClientAuth extends CertificateMethod implements CertificateIdentityBearingMethodInterface
{
    public function __construct(
        private CertificateReaderInterface $certificates,
    ) {
    }

    public function name(): string
    {
        return 'tls_client_auth';
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $certificate = $request->certificate;
        $identity = $client->registration->certificateIdentity;
        if ($certificate === null || $identity === null) {
            throw ClientAuthenticationRequest::notAuthenticatedHere($client, $this);
        }
        try {
            $subject = $this->certificates->subjectOf($certificate);
        } catch (UnreadableCertificateException $exception) {
            throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::UnreadableCertificate,
                $client->registration->clientId,
                $this->name(),
                $exception->getMessage(),
                $exception,
            );
        }
        if (! $identity->matches($subject)) {
            throw $this->unexpectedCertificate($client, sprintf('the certificate presented does not carry the %s of the client', $identity->name()));
        }
    }

    /**
     * What an acceptance costs that a refusal must cost too is reading the certificate, which is done
     * whether or not there is a client to compare it to.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            return;
        }
        try {
            $this->certificates->subjectOf($certificate);
        } catch (UnreadableCertificateException) {
        }
    }
}
