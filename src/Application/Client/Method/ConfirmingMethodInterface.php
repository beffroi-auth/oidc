<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;

/**
 * RFC 8705 §3, RFC 7800 §3.1
 */
interface ConfirmingMethodInterface extends CertificateBindingMethodInterface, AuthenticationMethodInterface
{
    /**
     * Called only once the request is verified against the client, so what it reads is proven.
     */
    public function confirmationOf(ClientAuthenticationRequest $request): ConfirmationInterface;
}
