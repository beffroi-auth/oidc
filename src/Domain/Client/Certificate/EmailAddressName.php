<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function array_any;
use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * "tls_client_auth_san_email" (RFC 8705 §2.1.2): the expected rfc822Name entry of the subject alternative
 * name extension, compared as the text it is. The local part of an address is case-sensitive (RFC 5321
 * §2.4), and a provider has no way of knowing what the domain of a client does with case, so nothing is
 * folded.
 */
final readonly class EmailAddressName implements CertificateIdentityInterface
{
    /**
     * The registration metadata this kind is registered under (RFC 8705 §2.1.2).
     */
    public const string NAME = 'tls_client_auth_san_email';

    public function __construct(
        public string $emailAddress,
    ) {
        if ($emailAddress === '') {
            throw new InvalidArgumentException('A registered rfc822Name is not empty (RFC 8705 section 2.1.2).');
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function matches(CertificateSubject $subject): bool
    {
        return array_any($subject->emailAddresses, fn (string $entry): bool => hash_equals($this->emailAddress, $entry));
    }
}
