<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Certificate;

use function array_any;
use function hash_equals;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * "tls_client_auth_san_uri" (RFC 8705 §2.1.2): the expected uniformResourceIdentifier entry of the
 * subject alternative name extension, compared as the text it is. A URI is not normalised before the
 * comparison: RFC 3986 §6.2.1 makes two URIs that differ equivalent only under rules a certificate does
 * not carry, and a provider that guessed them would accept a name nobody registered.
 */
final readonly class UriName implements CertificateIdentityInterface
{
    public function __construct(
        public string $uri,
    ) {
        if ($uri === '') {
            throw new InvalidArgumentException('A registered uniformResourceIdentifier is not empty (RFC 8705 section 2.1.2).');
        }
    }

    public function name(): string
    {
        return 'tls_client_auth_san_uri';
    }

    public function matches(CertificateSubject $subject): bool
    {
        return array_any($subject->uris, fn (string $entry): bool => hash_equals($this->uri, $entry));
    }
}
