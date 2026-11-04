<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;

/**
 * RFC 7523 §3
 */
interface TrustedIssuersInterface
{
    /**
     * @param string $issuer the "iss" of an assertion, compared byte for byte
     */
    public function find(Tenant $tenant, string $issuer): ?TrustedIssuer;
}
