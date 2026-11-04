<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * For the audit trail; the client only reads "invalid_request" or "invalid_client" (RFC 6749 §5.2).
 */
enum ClientAuthenticationFailureReason: string
{
    case MalformedCredentials = 'malformed_credentials';

    /**
     * RFC 6749 §2.3
     */
    case MultipleMechanisms = 'multiple_mechanisms';

    case MismatchedClientId = 'mismatched_client_id';

    case UnsupportedScheme = 'unsupported_scheme';

    case NoCredentials = 'no_credentials';

    case UnknownClient = 'unknown_client';

    case UnexpectedMethod = 'unexpected_method';

    case InvalidSecret = 'invalid_secret';

    /**
     * RFC 7523 §3
     */
    case InvalidAssertion = 'invalid_assertion';

    /**
     * RFC 7523 §3
     */
    case ReplayedAssertion = 'replayed_assertion';

    case UnreadableClientKeys = 'unreadable_client_keys';

    /**
     * RFC 8705 §2
     */
    case UnexpectedCertificate = 'unexpected_certificate';

    case UnreadableCertificate = 'unreadable_certificate';
}
