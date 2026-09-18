<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 "access_denied": the resource owner refused.
 */
final class AccessDeniedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('access_denied', $description, 400, true);
    }
}
