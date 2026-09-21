<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\Certificate\CertificateSubject;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Exception\UnreadableCertificateException;

/**
 * What an X.509 certificate says about who presented it (RFC 5280 §4.1.2.6, §4.2.1.6), and how a name
 * registered for a client is written down. The two go together and are one port on purpose: RFC 8705
 * §2.1.2 asks for a predictable treatment of distinguished names, and the only way two names compare
 * predictably is that the same reader wrote both of them.
 */
interface CertificateReaderInterface
{
    /**
     * @throws UnreadableCertificateException when the bytes are not an X.509 certificate
     */
    public function subjectOf(ClientCertificate $certificate): CertificateSubject;

    /**
     * A distinguished name as a registration writes it (RFC 4514), written back the way this reader
     * writes the one it reads out of a certificate.
     *
     * @throws UnreadableCertificateException when the value is not a distinguished name
     */
    public function distinguishedName(string $value): string;
}
