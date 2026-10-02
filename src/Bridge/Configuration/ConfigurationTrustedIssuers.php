<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\TrustedIssuersInterface;

/**
 * The third parties declared in the configuration (architecture §5.1), validated at boot. They belong to the
 * tenant this deployment declares, which is why the repository is told its slug: an issuer one tenant trusts is
 * unknown to another, and asked about another tenant this answers as if there were none.
 */
final readonly class ConfigurationTrustedIssuers implements TrustedIssuersInterface
{
    /**
     * @var array<string, TrustedIssuer>
     */
    private array $issuers;

    /**
     * @param array<string, array<string, mixed>> $definitions by the "iss" the issuer signs with
     */
    public function __construct(
        private string $tenantSlug,
        array $definitions,
        SignatureAlgorithmsInterface $algorithms,
    ) {
        $issuers = [];
        foreach ($definitions as $issuer => $definition) {
            $issuers[(string) $issuer] = TrustedIssuerDefinition::fromArray((string) $issuer, $definition, $algorithms)->issuer;
        }
        $this->issuers = $issuers;
    }

    public function find(Tenant $tenant, string $issuer): ?TrustedIssuer
    {
        return $tenant->slug === $this->tenantSlug ? $this->issuers[$issuer] ?? null : null;
    }
}
