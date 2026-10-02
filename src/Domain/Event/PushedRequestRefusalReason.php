<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * Why a "request_uri" of RFC 9126 §2.2 granted nothing. For the audit trail; the client only reads
 * "invalid_request_uri" (OIDC Core §3.1.2.6), the four cases being one answer to whoever presents one.
 */
enum PushedRequestRefusalReason: string
{
    /**
     * A reference shaped like one of ours that names no record: never issued, or dropped since.
     */
    case Unknown = 'unknown_request_uri';

    case Expired = 'expired_request_uri';

    /**
     * RFC 9126 §4: one use.
     */
    case AlreadyUsed = 'already_used_request_uri';

    /**
     * RFC 9126 §2.2: the reference is bound to the client that pushed it.
     */
    case OtherClient = 'other_client';
}
