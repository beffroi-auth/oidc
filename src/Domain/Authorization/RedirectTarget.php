<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;

/**
 * What the first stage of RFC 6749 §4.1.2.1 establishes before anything else is looked at: a known
 * client, a redirect URI registered for it, and the state to echo. Only once this exists may an error
 * be sent back to the client instead of being shown to the user (RFC 9700 §4.1).
 */
final readonly class RedirectTarget
{
    /**
     * @param string|null $state the client's state, echoed as is in every response (RFC 6749 §4.1.2, §4.1.2.1)
     */
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        public ?string $state,
    ) {
    }
}
