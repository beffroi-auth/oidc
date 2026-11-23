<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\CertificateIdentityBearingMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\ClientNotAuthenticatedHereException;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use Beffroi\Oidc\Port\ClientCertificateAuthoritiesInterface;
use function sprintf;

/**
 * RFC 8705 §2.1, §7.4
 *
 * The listener hands over the leaf without judging it, so the chain and the validity are checked here; revocation is
 * left to the deployment, as §2.1 allows.
 */
final readonly class TlsClientAuth extends CertificateMethod implements CertificateIdentityBearingMethodInterface
{
    public function __construct(
        private CertificateReaderInterface $certificates,
        private ClientCertificateAuthoritiesInterface $authorities,
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
            throw new ClientNotAuthenticatedHereException($client, $this);
        }
        try {
            $issued = $this->authorities->issued($certificate, $request->context->receivedAt);
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
        if (! $issued) {
            throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::UntrustedCertificate,
                $client->registration->clientId,
                $this->name(),
                'the certificate presented was not issued by an authority the provider trusts, or is not valid now',
            );
        }
        if (! $identity->matches($subject)) {
            throw $this->unexpectedCertificate($client, sprintf('the certificate presented does not carry the %s of the client', $identity->name()));
        }
    }

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            return;
        }
        try {
            $this->authorities->issued($certificate, $request->context->receivedAt);
            $this->certificates->subjectOf($certificate);
        } catch (UnreadableCertificateException) {
        }
    }
}
