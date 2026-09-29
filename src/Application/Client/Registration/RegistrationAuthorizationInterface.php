<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;

/**
 * One way a registration request is authorised (decision 0009). One class per mode, wired into the
 * provider and named by the registration policy of a tenant: a mode the provider gains is a class added
 * and a line of wiring, never a case added to something that knows how many there are. Closed is no mode
 * at all, the absence of the endpoint rather than a mode that refuses.
 *
 * A mode is compared to a literal in the class that is that mode and nowhere else: this one names
 * itself, and what picks among them compares names (`RegistrationAuthorizations`).
 *
 * What it answers with is what it puts in front of the members the client sent, because RFC 7591 §3.1.1
 * makes that the same decision: an authorisation that trusts a statement its issuer signed is also the
 * one that says those members outrank the ones sent in the clear. A mode that reads nothing of the body
 * puts nothing in front of it.
 */
interface RegistrationAuthorizationInterface
{
    /**
     * The name a registration policy names this mode by (decision 0009).
     *
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * The policy is the one that named this mode, and it carries what the tenant wrote about it: the
     * authorities whose statements the attested mode accepts are the tenant's and nothing global, as the
     * mode itself is. A mode that needs nothing of it reads nothing of it.
     *
     * @throws UnauthorizedRegistrationException when the request presents nothing this mode acts on
     *
     * @return list<ClientMetadataSourceInterface> what this mode puts in front of the members the client
     *                                             sent, in the order they win; empty for a mode that
     *                                             reads none
     */
    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): array;
}
