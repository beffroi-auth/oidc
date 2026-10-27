<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Trust;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * What an assertion of a trusted issuer says once its signature and its claims have been judged
 * (RFC 7523 §3): who signed it, whom it is about, and what spends it, the identifier its issuer gave it and
 * the instant it expires, until which that identifier is remembered.
 *
 * The subject is the string the issuer wrote and not a user of this tenant: which user it names, if any, is
 * the linked identity of that issuer's source (decision 0002), and that is asked of the identities and not of
 * the assertion.
 */
final readonly class VerifiedAssertion
{
    /**
     * @param string $jti the identifier of the assertion, unique to the issuer that signed it
     * @param DateTimeImmutable $expiresAt when the assertion stops being valid
     */
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
