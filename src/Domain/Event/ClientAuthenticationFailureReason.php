<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

/**
 * For the audit trail; the client only reads "invalid_request" or "invalid_client" (RFC 6749 §5.2).
 */
enum ClientAuthenticationFailureReason: string
{
    case MalformedCredentials = 'malformed_credentials';

    /**
     * RFC 6749 §2.3: a secret in the header and another in the body.
     */
    case MultipleMechanisms = 'multiple_mechanisms';

    case MismatchedClientId = 'mismatched_client_id';

    case UnsupportedScheme = 'unsupported_scheme';

    case NoCredentials = 'no_credentials';

    case UnknownClient = 'unknown_client';

    /**
     * Not the method the client is registered with.
     */
    case UnexpectedMethod = 'unexpected_method';

    case InvalidSecret = 'invalid_secret';
}
