<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;

interface RegistrationAuthorizationInterface
{
    /**
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * @throws UnauthorizedRegistrationException
     * @throws UnreadableClientMetadataException
     *
     * @return list<ClientMetadataSourceInterface> put in front of the members the client sent, the first winning
     */
    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): array;
}
