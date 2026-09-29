<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;

/**
 * Remembers the "jti" of a software statement until it expires (RFC 7591 §2.3), so that one statement
 * registers one client. The store outlives the request and is shared by the workers of a deployment: a
 * statement replayed on another worker is a replay all the same.
 *
 * It shares nothing with the guards of the assertions a client authenticates with or presents as an
 * authorization (RFC 7523 §2.1): the readings of a signed thing never share a store, so that one
 * accepted here is not thereby accepted there by having been remembered in the same place.
 */
interface SoftwareStatementReplayGuardInterface
{
    /**
     * @param string $jti the identifier of the statement, unique to the authority that signed it
     * @param DateTimeImmutable $expiresAt when the statement stops being valid, after which it may be forgotten
     *
     * @return bool true when the identifier had not been seen and is now remembered, false when it had
     */
    public function remember(Tenant $tenant, StatementIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool;
}
