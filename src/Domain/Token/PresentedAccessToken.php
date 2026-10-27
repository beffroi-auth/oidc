<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use SensitiveParameter;

/**
 * An access token as a protected resource received it: the value, and the scheme it was presented under
 * (RFC 6750 §2.1, RFC 9449 §7.1). How a request carries it is read before this, by the parser of the
 * Application that knows about headers and bodies; what is left here is what the provider reasons about.
 *
 * The scheme comes with the token, because a token is presented the way it was issued: one bound to a
 * key is sent under "DPoP" with a proof beside it (RFC 9449 §7.1), and whoever stole it and sends it as
 * a bearer token is refused. What it is bound to is read from the token, so that refusal comes once the
 * token has been verified.
 */
final readonly class PresentedAccessToken
{
    /**
     * @param string $scheme one of the schemes the resource serves, spelled as this provider spells it
     */
    public function __construct(
        public string $scheme,
        #[SensitiveParameter]
        public string $value,
    ) {
    }

    /**
     * Whether the token was presented the way a token bound like this is presented (RFC 9449 §7.1); a
     * token bound to nothing is a bearer token and is presented as one.
     */
    public function isPresentedAs(?ConfirmationInterface $confirmation): bool
    {
        return $this->scheme === ($confirmation?->scheme() ?? TokenResponse::BEARER);
    }
}
