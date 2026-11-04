<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function array_keys;
use function array_values;
use function count;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function sprintf;

/**
 * RFC 8705 §2.1.2
 */
final readonly class CertificateIdentities
{
    public const string SUBJECT_DN = SubjectDistinguishedName::NAME;

    public const string SAN_DNS = DnsName::NAME;

    public const string SAN_URI = UriName::NAME;

    public const string SAN_IP = IpAddressName::NAME;

    public const string SAN_EMAIL = EmailAddressName::NAME;

    public const array NAMES = [self::SUBJECT_DN, self::SAN_DNS, self::SAN_URI, self::SAN_IP, self::SAN_EMAIL];

    /**
     * @param array<string, string|null> $registration keyed by the five names
     *
     * @throws InvalidArgumentException when more than one is registered, or one is not a value of its kind
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
            self::SAN_EMAIL => new EmailAddressName($value),
            default => throw new InvalidArgumentException(sprintf('"%s" names no value of RFC 8705 section 2.1.2.', $name)),
        };
    }
}
