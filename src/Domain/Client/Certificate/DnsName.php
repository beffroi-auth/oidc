<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function array_any;
use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function strtolower;

/**
 * "tls_client_auth_san_dns" (RFC 8705 §2.1.2): the expected dNSName entry of the subject alternative
 * name extension. A domain name is compared without regard to case (RFC 4343 §1), and to nothing else: a
 * wildcard entry is a name like any other here, matched as the text it is and never expanded.
 */
final readonly class DnsName implements CertificateIdentityInterface
{
    /**
     * The registration metadata this kind is registered under (RFC 8705 §2.1.2).
     */
    public const string NAME = 'tls_client_auth_san_dns';

    public string $dnsName;

    public function __construct(string $dnsName)
    {
        if ($dnsName === '') {
            throw new InvalidArgumentException('A registered dNSName is not empty (RFC 8705 section 2.1.2).');
        }
        $this->dnsName = strtolower($dnsName);
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function matches(CertificateSubject $subject): bool
    {
        return array_any($subject->dnsNames, fn (string $entry): bool => hash_equals($this->dnsName, strtolower($entry)));
    }
}
