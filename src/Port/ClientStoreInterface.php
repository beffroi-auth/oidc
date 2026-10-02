<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRecord;

/**
 * The rows of the clients the provider registered itself (RFC 7591 §3.2.1, RFC 7592): where such a client
 * is written, read back at the endpoint where it reads and replaces itself, and removed when it deletes
 * itself.
 *
 * It is not the port a client is looked up through: what registers one never resolves one, and what
 * resolves one never learns that a client can be written at all. What comes out of here is the row and
 * never the `Client` a request is served against, which is what the source that reads those rows back
 * answers (`ClientSourceInterface`).
 */
interface ClientStoreInterface
{
    public function save(ClientRecord $record): void;

    /**
     * @return ClientRecord|null null when this store holds no such client of that tenant, which is what a
     *                           client nobody registered and a client that deleted itself look like
     */
    public function findRecord(Tenant $tenant, string $clientId): ?ClientRecord;

    /**
     * RFC 7592 §2.3: the client is gone, and so is what only it could have done. What becomes of the
     * consents, the grants and the token families that named it is the business of whoever answers for
     * rows that can no longer do anything; nothing here reads them.
     */
    public function remove(ClientRecord $record): void;
}
