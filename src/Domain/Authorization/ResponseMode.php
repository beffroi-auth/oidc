<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 "response_mode". The default of the code flow is
 * "query" and it is the only one served in the first spike; "form_post" is deferred, "fragment" is not
 * for a code response (RFC 6749 §4.1.2).
 */
enum ResponseMode: string
{
    case Query = 'query';
}
