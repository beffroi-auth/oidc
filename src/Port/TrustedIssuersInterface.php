<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;

/**
 * The third parties a tenant trusts the signature of (RFC 7523 §3). A closed registration read by the tenant
 * that holds it: an issuer one tenant trusts is unknown to another, and an issuer nobody registered is
 * unknown to everybody.
 */
interface TrustedIssuersInterface
{
    /**
     * @param string $issuer the "iss" an assertion carries, compared byte for byte
     *
     * @return TrustedIssuer|null null when this tenant trusts nobody by that name
     */
    public function find(Tenant $tenant, string $issuer): ?TrustedIssuer;
}
