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
 * RFC 8705 §2, §3.1
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
     * @throws LogicException when the request carries no certificate
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
     * Nothing secret is compared; a kind that does work before comparing pays for it here.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }

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
