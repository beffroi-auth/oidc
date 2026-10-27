<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Client\AddressedFormat;

/**
 * What the ID token of a response needs from outside the provider, read before it is struck (OIDC Core §3.1.3.7,
 * architecture §4.6): the shape its client registered for it, addressed (AddressedFormat), and the kind of "sub"
 * that client registered, opened, whose pairwise kind computes the "sub" with a salt of the tenant the KMS opens
 * (OIDC Core §8.1). Whoever spends something on the way to an ID token reads both first, and striking the token
 * then depends on nothing the KMS or the client serves.
 */
final readonly class AddressedIdToken
{
    public function __construct(
        public AddressedFormat $format,
        public OpenedSubjectIdentifierInterface $subjectIdentifier,
    ) {
    }
}
