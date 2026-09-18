<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1; "query" is the only one served, "form_post" is deferred.
 */
enum ResponseMode: string
{
    case Query = 'query';
}
