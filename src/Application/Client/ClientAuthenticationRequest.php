<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use function is_string;

/**
 * One request at an endpoint that authenticates a client (RFC 6749 §2.3), as the methods read it: the
 * header it carries, the form parameters it carries, the credentials of it that are already read, and
 * the URL of the endpoint that received it, which an assertion may name as its audience (RFC 7523 §3).
 *
 * A credential a value object stands for is read once, before any method sees the request, and is
 * carried here as that value object: the certificate the connection proved (RFC 8705 §2), read at the
 * edge, and the assertion the body carries (RFC 7523 §2.2), read by ClientAuthenticationRequestParser
 * with the reader the provider is wired with. Two methods that read the same one therefore read what
 * was read once, and nothing here calls a port or keeps a state of its own.
 */
final readonly class ClientAuthenticationRequest
{
    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request
     * @param array<string, mixed> $parameters the form parameters of the request body, the credential ones known to be strings
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake, null when it presented none, which is the ordinary case (RFC 8705 §2)
     * @param UnverifiedJwt|null $assertion the assertion the request carries, read and verified in nothing, null when it carries none
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
     * @return string|null null when the parameter is absent or empty, an empty credential being no
     *                     credential (RFC 6749 appendix A)
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
     * RFC 6749 §2.3.1: a secret in the body. An empty one is a secret all the same, presented and wrong,
     * so it is read as it is given.
     */
    public function secret(): ?string
    {
        $value = $this->parameters['client_secret'] ?? null;

        return is_string($value) ? $value : null;
    }
}
