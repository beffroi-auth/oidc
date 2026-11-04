<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

/**
 * RFC 5280 §4.1.2.6, §4.2.1.6
 */
final readonly class CertificateSubject
{
    /**
     * @param list<string> $dnsNames
     * @param list<string> $uris
     * @param list<string> $ipAddresses in their textual form
     * @param list<string> $emailAddresses
     */
    public function __construct(
        public string $distinguishedName,
        public array $dnsNames = [],
        public array $uris = [],
        public array $ipAddresses = [],
        public array $emailAddresses = [],
    ) {
    }
}
