<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Oidc\Domain\Client\RedirectUri;

/**
 * Where the user agent is sent once the logout is done (RP-Initiated Logout §3): a registered URI, "state"
 * echoed, no "iss" (RFC 9207 covers authorization responses only).
 */
final readonly class PostLogoutRedirect
{
    public function __construct(
        public RedirectUri $redirectUri,
        public ?string $state,
    ) {
    }

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
