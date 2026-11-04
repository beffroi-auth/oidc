<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * RFC 8705 §3.1
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
