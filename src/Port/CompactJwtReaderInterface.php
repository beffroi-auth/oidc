<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * RFC 7519 §7.2
 */
interface CompactJwtReaderInterface
{
    /**
     * @throws InvalidJwtException
     */
    public function read(string $jwt): UnverifiedJwt;
}
