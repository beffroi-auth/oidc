<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * What the first stage of RFC 6749 §4.1.2.1 establishes; only once this exists may an error be sent back
 * to the client (RFC 9700 §4.1). The response mode belongs here rather than to the request: it says how
 * anything reaches the client, a refusal of the second stage as well as a code (OIDC Core §3.1.2.6). It is
 * the name a way of answering gives itself, resolved against what the integration wired before it is
 * written here, so that what is carried is a mode that delivers and never an alias nor a name nothing
 * answers (ServedResponseModesInterface).
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
