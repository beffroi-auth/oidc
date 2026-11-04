<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRecord;

/**
 * The rows of the clients that registered themselves (RFC 7591 §3.2.1, RFC 7592).
 */
interface ClientStoreInterface
{
    public function save(ClientRecord $record): void;

    public function findRecord(Tenant $tenant, string $clientId): ?ClientRecord;

    /**
     * RFC 7592 §2.3
     */
    public function remove(ClientRecord $record): void;
}
