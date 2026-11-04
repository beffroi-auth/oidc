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
 * RFC 8705 §2.1.2
 *
 * Compared as octets: RFC 4291 §2.2 lets one address be written several ways.
 */
final readonly class IpAddressName implements CertificateIdentityInterface
{
    public const string NAME = 'tls_client_auth_san_ip';

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
