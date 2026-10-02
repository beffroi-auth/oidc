<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * Binding to the certificate the client presented at the TLS handshake (RFC 8705 §3.1). The token stays
 * a bearer token on the wire: the transport proves the holder again at every request, and the client
 * changes nothing to the way it presents its token.
 */
final readonly class CertificateConfirmationKind implements ConfirmationKindInterface
{
    public function member(): string
    {
        return CertificateConfirmation::MEMBER;
    }

    public function scheme(): string
    {
        return TokenResponse::BEARER;
    }

    public function of(string $thumbprint): ConfirmationInterface
    {
        return new CertificateConfirmation($thumbprint);
    }
}
