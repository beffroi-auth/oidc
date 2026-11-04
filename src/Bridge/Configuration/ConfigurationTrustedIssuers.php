<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\TrustedIssuersInterface;

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
