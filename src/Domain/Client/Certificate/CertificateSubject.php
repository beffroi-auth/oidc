<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Certificate;

/**
 * What a certificate says about who presented it (RFC 5280 §4.1.2.6, §4.2.1.6), read out of it by a
 * CertificateReaderInterface: the subject distinguished name, and the entries of the subject alternative
 * name extension RFC 8705 §2.1.2 lets a client register itself under. Nothing else of the certificate is
 * read, because nothing else names the client.
 *
 * The distinguished name is the RFC 4514 form the reader writes, and a registered name is normalised by
 * that same reader, so that the two sides of a comparison are written the same way (RFC 8705 §2.1.2,
 * which asks for a predictable treatment of distinguished names).
 */
final readonly class CertificateSubject
{
    /**
     * @param list<string> $dnsNames the dNSName entries
     * @param list<string> $uris the uniformResourceIdentifier entries
     * @param list<string> $ipAddresses the iPAddress entries, in their textual form
     * @param list<string> $emailAddresses the rfc822Name entries
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
