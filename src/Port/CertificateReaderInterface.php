<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\Certificate\CertificateSubject;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\UnreadableCertificateException;

/**
 * One port for both readings: two distinguished names compare predictably only when one reader wrote both
 * (RFC 8705 §2.1.2).
 */
interface CertificateReaderInterface
{
    /**
     * @throws UnreadableCertificateException
     */
    public function subjectOf(ClientCertificate $certificate): CertificateSubject;

    /**
     * A registered distinguished name (RFC 4514), written the way this reader writes the one of a certificate.
     *
     * @throws UnreadableCertificateException
     */
    public function distinguishedName(string $value): string;
}
