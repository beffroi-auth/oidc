<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Certificate;

use function array_keys;
use function array_values;
use function count;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function sprintf;

/**
 * The five ways RFC 8705 §2.1.2 lets a client register itself, read from a registration. A client that
 * authenticates with "tls_client_auth" registers exactly one of them: several would be several rules for
 * one certificate, where the specification names one expected value.
 *
 * This is the whole of §2.1.2 and the only place the five names are written down; a sixth kind the
 * specification added would be a class beside the other five and a line here.
 */
final readonly class CertificateIdentities
{
    public const string SUBJECT_DN = 'tls_client_auth_subject_dn';

    public const string SAN_DNS = 'tls_client_auth_san_dns';

    public const string SAN_URI = 'tls_client_auth_san_uri';

    public const string SAN_IP = 'tls_client_auth_san_ip';

    public const string SAN_EMAIL = 'tls_client_auth_san_email';

    /**
     * In the order of RFC 8705 §2.1.2.
     */
    public const array NAMES = [self::SUBJECT_DN, self::SAN_DNS, self::SAN_URI, self::SAN_IP, self::SAN_EMAIL];

    /**
     * @param array<string, string|null> $registration the five names, each one the value registered or null
     *
     * @throws InvalidArgumentException when more than one is registered, or when one of them is not a
     *                                  value of its kind
     */
    public static function fromRegistration(array $registration): ?CertificateIdentityInterface
    {
        $registered = [];
        foreach (self::NAMES as $name) {
            $value = $registration[$name] ?? null;
            if ($value !== null) {
                $registered[$name] = self::named($name, $value);
            }
        }
        if (count($registered) > 1) {
            throw new InvalidArgumentException(sprintf('A client registers exactly one of the values of RFC 8705 section 2.1.2, not %s.', implode(
                ' and ',
                array_keys($registered),
            )));
        }

        return array_values($registered)[0] ?? null;
    }

    private static function named(string $name, string $value): CertificateIdentityInterface
    {
        return match ($name) {
            self::SUBJECT_DN => new SubjectDistinguishedName($value),
            self::SAN_DNS => new DnsName($value),
            self::SAN_URI => new UriName($value),
            self::SAN_IP => new IpAddressName($value),
            default => new EmailAddressName($value),
        };
    }
}
