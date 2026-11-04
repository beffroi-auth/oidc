<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

interface AuthenticationMethodInterface extends ClientAuthenticationMethodInterface
{
    /**
     * RFC 6749 §2.3
     *
     * What of the request the method reads: two methods reading the same thing are one mechanism.
     *
     * @return non-empty-string
     */
    public function mechanism(): string;

    /**
     * The client identifier the request claims under this method, null when it does not present the method.
     *
     * @throws ClientAuthenticationFailure when the request presents this method wrongly
     */
    public function presentedBy(ClientAuthenticationRequest $request): ?string;

    /**
     * @throws ClientAuthenticationFailure
     */
    public function verify(ClientAuthenticationRequest $request, Client $client): void;

    /**
     * Takes the time of an acceptance when nothing can be verified, so timing never tells who is registered.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void;
}
