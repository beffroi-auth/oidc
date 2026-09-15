<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

/**
 * Why a client failed to authenticate at the token endpoint, for the audit trail. The client itself only
 * reads "invalid_request" or "invalid_client" (RFC 6749 §5.2).
 */
enum ClientAuthenticationFailureReason: string
{
    /**
     * The Authorization header or the form parameters could not be read as client credentials.
     */
    case MalformedCredentials = 'malformed_credentials';

    /**
     * RFC 6749 §2.3: a secret in the Authorization header and another one in the body.
     */
    case MultipleMechanisms = 'multiple_mechanisms';

    /**
     * The client_id of the body is not the one of the Authorization header.
     */
    case MismatchedClientId = 'mismatched_client_id';

    /**
     * The Authorization header carries a scheme other than Basic.
     */
    case UnsupportedScheme = 'unsupported_scheme';

    /**
     * Neither a client_id nor credentials.
     */
    case NoCredentials = 'no_credentials';

    case UnknownClient = 'unknown_client';

    /**
     * The method used is not the one the client is registered with.
     */
    case UnexpectedMethod = 'unexpected_method';

    case InvalidSecret = 'invalid_secret';
}
