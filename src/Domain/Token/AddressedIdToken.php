<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Client\AddressedFormat;

/**
 * What the ID token of a response needs from outside the provider, read before it is struck.
 */
final readonly class AddressedIdToken
{
    public function __construct(
        public AddressedFormat $format,
        public OpenedSubjectIdentifierInterface $subjectIdentifier,
    ) {
    }
}
