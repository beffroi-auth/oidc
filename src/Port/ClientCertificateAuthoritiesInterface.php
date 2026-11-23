<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use DateTimeImmutable;

/**
 * RFC 8705 §2.1, §7.4, RFC 5280 §6.1
 */
interface ClientCertificateAuthoritiesInterface
{
    /**
     * Whether one of the authorities issued the certificate and the certificate is valid at that moment.
     *
     * @throws UnreadableCertificateException
     */
    public function issued(ClientCertificate $certificate, DateTimeImmutable $at): bool;
}
