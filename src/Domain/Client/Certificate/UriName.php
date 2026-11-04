<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function array_any;
use function hash_equals;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 8705 §2.1.2
 *
 * Compared as text, never normalised: guessing at RFC 3986 §6.2.1 would accept a name nobody registered.
 */
final readonly class UriName implements CertificateIdentityInterface
{
    public const string NAME = 'tls_client_auth_san_uri';

    public function __construct(
        public string $uri,
    ) {
        if ($uri === '') {
            throw new InvalidArgumentException('A registered uniformResourceIdentifier is not empty (RFC 8705 section 2.1.2).');
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function matches(CertificateSubject $subject): bool
    {
        return array_any($subject->uris, fn (string $entry): bool => hash_equals($this->uri, $entry));
    }
}
