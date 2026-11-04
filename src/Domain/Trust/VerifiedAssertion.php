<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Trust;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 7523 §3
 *
 * The subject is the string the issuer wrote; it names a user only through a linked identity (decision 0002).
 */
final readonly class VerifiedAssertion
{
    public function __construct(
        public TrustedIssuer $issuer,
        public string $subject,
        public string $jti,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($subject === '') {
            throw new InvalidArgumentException('An assertion is about somebody (RFC 7523 section 3).');
        }
    }
}
