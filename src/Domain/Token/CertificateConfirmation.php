<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function hash_equals;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * A token bound to the certificate the client presented at the TLS handshake (RFC 8705 §3.1), named by
 * the SHA-256 thumbprint of its DER encoding. The token stays a bearer token on the wire: what the
 * transport proves, the transport proves again at every request, and the client changes nothing to the
 * way it presents its token.
 */
final readonly class CertificateConfirmation implements ConfirmationInterface
{
    public const string MEMBER = 'x5t#S256';

    /**
     * @param string $thumbprint the "x5t#S256" of RFC 8705 §3.1, base64url without padding
     */
    public function __construct(
        public string $thumbprint,
    ) {
        if ($thumbprint === '') {
            throw new InvalidArgumentException('A confirmation names the certificate it binds a token to (RFC 8705 section 3.1).');
        }
    }

    public static function ofCertificate(ClientCertificate $certificate): self
    {
        return new self($certificate->x5tS256());
    }

    public function member(): string
    {
        return self::MEMBER;
    }

    public function value(): string
    {
        return $this->thumbprint;
    }

    public function scheme(): string
    {
        return TokenResponse::BEARER;
    }

    public function toClaims(): array
    {
        return [
            ConfirmationInterface::CLAIM => [
                self::MEMBER => $this->thumbprint,
            ],
        ];
    }

    public function matches(ConfirmationInterface $other): bool
    {
        return $other->member() === self::MEMBER && hash_equals($this->thumbprint, $other->value());
    }
}
