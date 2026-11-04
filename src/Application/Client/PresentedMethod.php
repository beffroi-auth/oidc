<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;

final readonly class PresentedMethod
{
    public function __construct(
        public AuthenticationMethodInterface $method,
        public string $clientId,
    ) {
    }

    public function authenticatesClient(): bool
    {
        return $this->method->authenticatesClient();
    }

    public function bindsACertificate(): bool
    {
        return $this->method instanceof CertificateBindingMethodInterface;
    }

    /**
     * @return non-empty-string
     */
    public function mechanism(): string
    {
        return $this->method->mechanism();
    }

    /**
     * @return non-empty-string
     */
    public function name(): string
    {
        return $this->method->name();
    }
}
