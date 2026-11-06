<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;

/**
 * The Dynamic OP profile needs it: the conformance suite registers clients with no credential at all.
 */
final readonly class OpenRegistrationAuthorization implements RegistrationAuthorizationInterface
{
    public const string MODE = 'open';

    public function name(): string
    {
        return self::MODE;
    }

    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): AuthorizedRegistration
    {
        return new AuthorizedRegistration();
    }
}
