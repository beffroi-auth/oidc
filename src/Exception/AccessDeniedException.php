<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 "access_denied": the resource owner refused. Raised from the consent page, so the
 * client and its redirect URI are known and the error is sent back to the client.
 */
final class AccessDeniedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('access_denied', $description, 400, true);
    }
}
