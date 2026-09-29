<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;

/**
 * What a deployment wrote about the clients that register themselves (architecture §5.1, decision 0009).
 * A deployment that named no mode has no policy, which is closed: no registration endpoint for that
 * tenant, in the document as on the wire. An empty name is no name, which is what an environment
 * variable nobody set gives.
 *
 * The policy declared here is the policy of the tenant this deployment declares, named by its slug, as
 * the clients declared here are its clients: anything asked about another tenant is answered as a tenant
 * this deployment says nothing about, which is a tenant that registers nobody.
 */
final readonly class ConfigurationClientRegistrationPolicy implements ClientRegistrationPolicyInterface
{
    /**
     * @param string|null $mode what authorises a registration on this tenant, under the name the class that is that mode gives itself; null or empty for a deployment that registers nobody
     * @param bool $exemptsConfidentialClientsFromPkce decision 0017
     * @param DateInterval|null $keepsAClientUnusedFor decision 0009; null for the default of the policy
     * @param DateInterval|null $keepsAClientNeverUsedFor decision 0009; null for the default of the policy
     */
    public function __construct(
        private string $tenantSlug,
        private ?string $mode = null,
        private bool $exemptsConfidentialClientsFromPkce = false,
        private ?DateInterval $keepsAClientUnusedFor = null,
        private ?DateInterval $keepsAClientNeverUsedFor = null,
    ) {
    }

    public function policyFor(Tenant $tenant): ?ClientRegistrationPolicy
    {
        if ($tenant->slug !== $this->tenantSlug || $this->mode === null || $this->mode === '') {
            return null;
        }

        return new ClientRegistrationPolicy(
            $this->mode,
            $this->exemptsConfidentialClientsFromPkce,
            $this->keepsAClientUnusedFor ?? new DateInterval(ClientRegistrationPolicy::UNUSED_FOR),
            $this->keepsAClientNeverUsedFor ?? new DateInterval(ClientRegistrationPolicy::NEVER_USED_FOR),
        );
    }
}
