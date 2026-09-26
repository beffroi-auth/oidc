<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Trust;

use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What an assertion of a trusted issuer says once its signature and its claims have been judged
 * (RFC 7523 §3): who signed it, and whom it is about.
 *
 * The subject is the string the issuer wrote and not a user of this tenant: which user it names, if any, is
 * the linked identity of that issuer's source (decision 0002), and that is asked of the identities and not of
 * the assertion.
 */
final readonly class VerifiedAssertion
{
    public function __construct(
        public TrustedIssuer $issuer,
        public string $subject,
    ) {
        if ($subject === '') {
            throw new InvalidArgumentException('An assertion is about somebody (RFC 7523 section 3).');
        }
    }
}
