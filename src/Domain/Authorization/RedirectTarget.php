<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * RFC 6749 §4.1.2.1, RFC 9700 §4.1
 *
 * Only once the first stage has established it may an error be sent back to the client.
 */
final readonly class RedirectTarget
{
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        public ?string $state,
        public string $responseMode = ResponseModeNames::DEFAULT,
    ) {
    }
}
