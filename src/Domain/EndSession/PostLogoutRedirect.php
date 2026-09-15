<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Oidc\Domain\Client\RedirectUri;

/**
 * Where the user agent is sent once the logout is done (OIDC RP-Initiated Logout 1.0 §3): the
 * post_logout_redirect_uri the client presented, byte for byte equal to one it registered, with "state"
 * echoed when the request carried one. Nothing else: no code, no "iss" (RFC 9207 covers authorization
 * responses only), and never a URI the client did not register.
 */
final readonly class PostLogoutRedirect
{
    public function __construct(
        public RedirectUri $redirectUri,
        public ?string $state,
    ) {
    }

    /**
     * The URI the user agent is sent to.
     */
    public function toUri(): string
    {
        if ($this->state === null) {
            return (string) $this->redirectUri;
        }

        return $this->redirectUri->withParameters([
            'state' => $this->state,
        ]);
    }
}
