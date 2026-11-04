<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use function is_string;

final readonly class ClientAuthenticationRequest
{
    /**
     * @param string $endpoint absolute URL
     * @param array<string, mixed> $parameters the credential ones known to be strings
     */
    public function __construct(
        public Tenant $tenant,
        public string $endpoint,
        public ?string $authorizationHeader,
        private array $parameters,
        public RequestContext $context,
        public ?ClientCertificate $certificate,
        public ?UnverifiedJwt $assertion,
    ) {
    }

    /**
     * @return string|null null when absent or empty
     */
    public function parameter(string $name): ?string
    {
        $value = $this->parameters[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function clientId(): ?string
    {
        return $this->parameter('client_id');
    }

    /**
     * RFC 6749 §2.3.1
     *
     * An empty secret is read as given: presented and wrong, never absent.
     */
    public function secret(): ?string
    {
        $value = $this->parameters['client_secret'] ?? null;

        return is_string($value) ? $value : null;
    }
}
