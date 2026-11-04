<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;

/**
 * What a deployment wrote about the clients that register themselves (architecture §5.1, decision 0009).
 * A deployment that named no mode has no policy, which is closed: no registration endpoint for that
 * tenant, in the document as on the wire. An empty name is no name, which is what an environment
 * variable declared empty gives.
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
     * What a registration that names no scope is registered with here (RFC 7591 §2), read once at the boot
     * that declared it: a deployment that writes a scope this provider does not read is told so then, and
     * not at the first registration. Null for a deployment that wrote none, and an empty string is none,
     * which is what an environment variable declared empty gives.
     */
    private ?Scopes $defaultScopes;

    /**
     * @param string|null $mode what authorises a registration on this tenant, under the name the class that is that mode gives itself; null or empty for a deployment that registers nobody
     * @param bool $exemptsConfidentialClientsFromPkce decision 0017
     * @param DateInterval|null $keepsAClientUnusedFor decision 0009; null for the default of the policy
     * @param DateInterval|null $keepsAClientNeverUsedFor decision 0009; null for the default of the policy
     * @param array<string, array<string, mixed>> $statementIssuers the authorities whose software statements this tenant accepts (RFC 7591 §2.3), keyed by the "iss" they sign with; none for a tenant that pins nobody, which is every tenant that declared none
     * @param SignatureAlgorithmsInterface|null $algorithms what the provider verifies a signature with, which an authority is pinned to sign with a subset of; null only where none is pinned, there being nothing to hold to it
     * @param string|null $defaultScope what a registration that names no scope is registered with (RFC 7591 §2), space-delimited as a request writes one (RFC 6749 §3.3); null or empty for a deployment that writes none
     *
     * @throws InvalidArgumentException when a declared authority or the declared default set of scopes does not hold together, which stops the boot rather than the first registration
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
        ?string $defaultScope = null,
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
        $this->defaultScopes = $defaultScope === null || $defaultScope === '' ? null : Scopes::parse($defaultScope);
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
            $this->defaultScopes,
        );
    }
}
