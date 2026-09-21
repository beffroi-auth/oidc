<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\CertificateIdentityBearingMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\Confirmation;
use Heidi\Oidc\Exception\LogicException;
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
final readonly class TlsClientAuth implements CertificateIdentityBearingMethodInterface, ConfirmingMethodInterface
{
    public function __construct(
        private CertificateReaderInterface $certificates,
    ) {
    }

    public function name(): string
    {
        return 'tls_client_auth';
    }

    public function mechanism(): string
    {
        return ClientAuthenticationRequest::CERTIFICATE;
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    /**
     * RFC 8705 §2: the client names itself in "client_id" and proves it with the certificate of the
     * connection. A request made without a certificate presents no mutual-TLS authentication at all, and
     * one made without "client_id" names nobody to look up.
     */
    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->certificate === null ? null : $request->clientId();
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $certificate = $request->certificate;
        $identity = $client->certificateIdentity;
        if ($certificate === null || $identity === null) {
            throw new LogicException(sprintf('The client "%s" is not authenticated by %s here.', $client->clientId, $this->name()));
        }
        try {
            $subject = $this->certificates->subjectOf($certificate);
        } catch (UnreadableCertificateException $exception) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnreadableCertificate, $client->clientId, $this->name(), $exception->getMessage(), $exception);
        }
        if (! $identity->matches($subject)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnexpectedCertificate, $client->clientId, $this->name(), sprintf('the certificate presented does not carry the %s of the client', $identity->name()));
        }
    }

    /**
     * A certificate is compared to what a registration says, and both are public: there is no secret
     * here to make a comparison constant over. What an acceptance costs that a refusal must cost too is
     * reading the certificate, which is done whether or not there is a client to compare it to.
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

    public function confirmationOf(ClientAuthenticationRequest $request): Confirmation
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            throw new LogicException(sprintf('A request that authenticated a client with %s carries a certificate.', $this->name()));
        }

        return Confirmation::ofCertificate($certificate);
    }
}
