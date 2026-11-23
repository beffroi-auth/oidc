<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * RFC 7519 §7.2, RFC 7515 §4.1.11
 */
interface CompactJwtReaderInterface
{
    /**
     * @throws InvalidJwtException when the token is not a compact JWS of one signature whose payload is a JSON object,
     *                             or when its protected header names an extension of JOSE
     */
    public function read(string $jwt): UnverifiedJwt;
}
