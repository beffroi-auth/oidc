<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * For the audit trail; the client reads "invalid_request_uri" whatever the case (OIDC Core §3.1.2.6).
 */
enum PushedRequestRefusalReason: string
{
    case Unknown = 'unknown_request_uri';

    case Expired = 'expired_request_uri';

    /**
     * RFC 9126 §4
     */
    case AlreadyUsed = 'already_used_request_uri';

    /**
     * RFC 9126 §2.2
     */
    case OtherClient = 'other_client';
}
