<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;
use function sprintf;

/**
 * A relying party registered with a tenant (RFC 6749 §2, RFC 7591 §2): what it registered
 * (`ClientRegistration`, which answers for itself), the tenant it belongs to, and the shared secret in
 * the shape the provider keeps it.
 *
 * Whether a secret was registered is the registration's own business and is checked there. What is
 * checked here is the one thing only this class can see: that the secret it was handed is kept in a
 * shape the registered method verifies against.
 */
final readonly class Client
{
    /**
     * @param ClientSecretInterface|null $secret the shared secret the registered method needs, in the shape it verifies against; null when the method needs none
     *
     * @throws InvalidArgumentException when the secret does not match what the registration declared, or is kept in a shape the method cannot verify
     */
    public function __construct(
        public Tenant $tenant,
        public ClientRegistration $registration,
        #[SensitiveParameter]
        public ?ClientSecretInterface $secret = null,
    ) {
        if ($registration->registersASecret !== ($secret !== null)) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" is built with a secret its registration does not declare, or without the one it does.',
                $registration->clientId,
            ));
        }
        $method = $registration->authenticationMethod;
        if ($secret !== null && $method instanceof SecretBearingMethodInterface && ! $method->accepts($secret)) {
            throw new InvalidArgumentException(sprintf(
                'The secret of the client "%s" is not kept in a shape %s verifies against.',
                $registration->clientId,
                $method->name(),
            ));
        }
    }

    public function belongsTo(Tenant $tenant): bool
    {
        return $this->tenant->equals($tenant);
    }

    public function equals(self $other): bool
    {
        return $this->registration->clientId === $other->registration->clientId && $this->belongsTo($other->tenant);
    }
}
