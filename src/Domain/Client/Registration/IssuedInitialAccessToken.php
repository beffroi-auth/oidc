<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use SensitiveParameter;

/**
 * What issuing an initial access token answers, once (RFC 7591 §1.2, decision 0009): the record the
 * tenant keeps, and the value that record cannot give back.
 *
 * The two travel together exactly once, at the moment they are drawn, for the same reason a registration
 * answers its secret once: what the row holds is a digest, so whoever issues the token is the only one
 * who ever sees the value, and a tenant that loses it issues another rather than reading this one.
 */
final readonly class IssuedInitialAccessToken
{
    public function __construct(
        public InitialAccessToken $token,
        #[SensitiveParameter]
        public string $value,
    ) {
    }
}
