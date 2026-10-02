<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

/**
 * The client authentication methods the provider is wired with (OIDC Discovery §3), the one source of
 * truth over them: what the endpoints take, what a client may register and what the discovery document
 * announces all read this one, so that they cannot disagree (issue #98).
 */
interface ClientAuthenticationMethodsInterface
{
    /**
     * @return non-empty-list<ClientAuthenticationMethodInterface> in the order they are wired
     */
    public function clientAuthenticationMethods(): array;
}
