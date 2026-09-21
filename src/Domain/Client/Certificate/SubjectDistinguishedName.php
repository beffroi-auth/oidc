<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Certificate;

use function hash_equals;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * "tls_client_auth_subject_dn" (RFC 8705 §2.1.2): the expected subject distinguished name of the
 * certificate, in the string form of RFC 4514.
 *
 * The value is the one the certificate reader writes for the name it was given, and the name read out of
 * the certificate is written by that same reader, so what is compared here is two names written the same
 * way. That is the predictable treatment §2.1.2 asks for, and it is why nothing here takes a
 * distinguished name apart, let alone with a regular expression.
 */
final readonly class SubjectDistinguishedName implements CertificateIdentityInterface
{
    public function __construct(
        public string $distinguishedName,
    ) {
        if ($distinguishedName === '') {
            throw new InvalidArgumentException('A registered subject distinguished name is not empty (RFC 8705 section 2.1.2).');
        }
    }

    public function name(): string
    {
        return 'tls_client_auth_subject_dn';
    }

    public function matches(CertificateSubject $subject): bool
    {
        return hash_equals($this->distinguishedName, $subject->distinguishedName);
    }
}
