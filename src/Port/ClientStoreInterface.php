<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ClientRecord;

/**
 * Where a client the provider registers itself is written (RFC 7591 §3.2.1). It is not the port a client
 * is looked up through: what registers one never resolves one, and what resolves one never learns that a
 * client can be written at all. The source that reads those rows back is a `ClientSourceInterface` like
 * any other.
 */
interface ClientStoreInterface
{
    public function save(ClientRecord $record): void;
}
