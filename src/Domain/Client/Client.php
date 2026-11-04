<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;
use function sprintf;

final readonly class Client
{
    /**
     * @throws InvalidArgumentException when the secret does not fit the registered method
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
