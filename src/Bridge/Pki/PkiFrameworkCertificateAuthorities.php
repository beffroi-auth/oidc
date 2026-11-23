<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Pki;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Port\ClientCertificateAuthoritiesInterface;
use DateTimeImmutable;
use function sprintf;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use Throwable;

/**
 * RFC 5280 §6.1, §4.2.1.9
 *
 * Only the leaf reaches the provider, so each authority is a trust anchor that issues client certificates itself, and
 * the path it validates is the leaf alone.
 */
final readonly class PkiFrameworkCertificateAuthorities implements ClientCertificateAuthoritiesInterface
{
    /**
     * @var list<Certificate>
     */
    private array $authorities;

    /**
     * @param list<string> $authorities in PEM
     *
     * @throws InvalidArgumentException when one is no certificate, or the certificate of no certificate authority
     */
    public function __construct(array $authorities)
    {
        $read = [];
        foreach ($authorities as $authority) {
            $read[] = self::authority($authority);
        }
        $this->authorities = $read;
    }

    public function issued(ClientCertificate $certificate, DateTimeImmutable $at): bool
    {
        try {
            $path = CertificationPath::create(Certificate::fromDER($certificate->der));
        } catch (Throwable $exception) {
            throw new UnreadableCertificateException('The certificate presented is not an X.509 certificate.', 0, $exception);
        }
        $validation = PathValidationConfig::create($at, 1);
        foreach ($this->authorities as $authority) {
            try {
                $path->validate($validation->withTrustAnchor($authority));

                return true;
            } catch (PathValidationException) {
            }
        }

        return false;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function authority(string $pem): Certificate
    {
        try {
            $certificate = Certificate::fromPEM(PEM::fromString($pem));
        } catch (Throwable $exception) {
            throw new InvalidArgumentException(
                sprintf('An authority of client certificates is a certificate in PEM: %s', $exception->getMessage()),
                previous: $exception,
            );
        }
        $extensions = $certificate->tbsCertificate()->extensions();
        if (! $extensions->hasBasicConstraints() || ! $extensions->basicConstraints()->isCA()) {
            throw new InvalidArgumentException(sprintf(
                'The authority of client certificates "%s" is the certificate of no certificate authority (RFC 5280 §4.2.1.9).',
                $certificate->tbsCertificate()->subject()->toString(),
            ));
        }

        return $certificate;
    }
}
