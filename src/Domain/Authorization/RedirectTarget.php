<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;

/**
 * What the first stage of RFC 6749 §4.1.2.1 establishes; only once this exists may an error be sent back
 * to the client (RFC 9700 §4.1).
 */
final readonly class RedirectTarget
{
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        public ?string $state,
    ) {
    }
}
