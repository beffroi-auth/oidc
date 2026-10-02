<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function array_any;
use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function inet_pton;
use function is_string;
use function sprintf;

/**
 * "tls_client_auth_san_ip" (RFC 8705 §2.1.2): the expected iPAddress entry of the subject alternative
 * name extension, "in dotted decimal notation for IPv4 or colon-delimited hexadecimal for IPv6".
 *
 * An address is compared as the octets it stands for and not as the text it was written in, because the
 * two sides write it differently and both are right: a certificate carries four or sixteen octets
 * (RFC 5280 §4.2.1.6) and a registration carries the text of RFC 4291 §2.2, which allows the same address
 * to be written several ways. Whatever is not an address, an empty value included, reads back as no
 * octets at all and matches nothing.
 */
final readonly class IpAddressName implements CertificateIdentityInterface
{
    /**
     * The registration metadata this kind is registered under (RFC 8705 §2.1.2).
     */
    public const string NAME = 'tls_client_auth_san_ip';

    /**
     * The octets of the address, four or sixteen.
     */
    public string $octets;

    public function __construct(
        public string $ipAddress,
    ) {
        $octets = inet_pton($ipAddress);
        if (! is_string($octets)) {
            throw new InvalidArgumentException(sprintf('The registered iPAddress "%s" is not an IP address (RFC 8705 section 2.1.2).', $ipAddress));
        }
        $this->octets = $octets;
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function matches(CertificateSubject $subject): bool
    {
        return array_any($subject->ipAddresses, function (string $entry): bool {
            $octets = inet_pton($entry);

            return is_string($octets) && hash_equals($this->octets, $octets);
        });
    }
}
