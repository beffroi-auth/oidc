<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * RP-Initiated Logout §3
 *
 * No "iss": RFC 9207 covers authorization responses only.
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
