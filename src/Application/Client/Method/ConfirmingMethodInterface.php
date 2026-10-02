<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;

/**
 * A method that proves more than who the client is: it proves the client holds a key, and the tokens
 * issued on that request are bound to it (RFC 8705 §3, RFC 7800 §3.1). The domain says such a method
 * binds, which is what the discovery document announces; this says what the binding is made of, which
 * needs the request and therefore lives in the module.
 */
interface ConfirmingMethodInterface extends CertificateBindingMethodInterface, AuthenticationMethodInterface
{
    /**
     * Called once the request has been verified against the client, so what it reads is what was proven.
     */
    public function confirmationOf(ClientAuthenticationRequest $request): ConfirmationInterface;
}
