<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 8705 §2.1.2, RFC 4514
 *
 * Both sides are written by the same certificate reader, so the two strings are compared as they are.
 */
final readonly class SubjectDistinguishedName implements CertificateIdentityInterface
{
    public const string NAME = 'tls_client_auth_subject_dn';

    public function __construct(
        public string $distinguishedName,
    ) {
        if ($distinguishedName === '') {
            throw new InvalidArgumentException('A registered subject distinguished name is not empty (RFC 8705 section 2.1.2).');
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function matches(CertificateSubject $subject): bool
    {
        return hash_equals($this->distinguishedName, $subject->distinguishedName);
    }
}
