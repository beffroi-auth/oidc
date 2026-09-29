<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
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
     * @var list<StatementIssuer>
     */
    private array $pinned;

    /**
     * @param string|null $mode what authorises a registration on this tenant, under the name the class that is that mode gives itself; null or empty for a deployment that registers nobody
     * @param bool $exemptsConfidentialClientsFromPkce decision 0017
     * @param DateInterval|null $keepsAClientUnusedFor decision 0009; null for the default of the policy
     * @param DateInterval|null $keepsAClientNeverUsedFor decision 0009; null for the default of the policy
     * @param array<string, array<string, mixed>> $statementIssuers the authorities whose software statements this tenant accepts (RFC 7591 §2.3), keyed by the "iss" they sign with; none for a tenant that pins nobody, which is every tenant that declared none
     * @param SignatureAlgorithmsInterface|null $algorithms what the provider verifies a signature with, which an authority is pinned to sign with a subset of; null only where none is pinned, there being nothing to hold to it
     *
     * @throws InvalidArgumentException when a declared authority does not hold together, which stops the boot rather than the first registration
     * @throws LogicException when authorities are declared and nothing is wired to verify what they sign with
     */
    public function __construct(
        private string $tenantSlug,
        private ?string $mode = null,
        private bool $exemptsConfidentialClientsFromPkce = false,
        private ?DateInterval $keepsAClientUnusedFor = null,
        private ?DateInterval $keepsAClientNeverUsedFor = null,
        array $statementIssuers = [],
        ?SignatureAlgorithmsInterface $algorithms = null,
    ) {
        $pinned = [];
        if ($statementIssuers !== []) {
            if ($algorithms === null) {
                throw new LogicException('The registration policy pins the issuer of a software statement, and nothing is wired to verify what it signs with (RFC 7591 section 2.3).');
            }
            foreach ($statementIssuers as $issuer => $definition) {
                $pinned[] = StatementIssuerDefinition::fromArray((string) $issuer, $definition, $algorithms)->issuer;
            }
        }
        $this->pinned = $pinned;
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
            $this->pinned,
        );
    }
}
