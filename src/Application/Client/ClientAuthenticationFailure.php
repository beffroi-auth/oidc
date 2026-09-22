<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use RuntimeException;
use Throwable;

/**
 * What a client authentication method raises when it refuses. It never leaves the authenticator: one
 * place records the reason in the audit trail and decides what the client reads back, so that two
 * methods cannot say a refusal differently.
 */
final class ClientAuthenticationFailure extends RuntimeException
{
    /**
     * RFC 6749 §5.2: one description whatever the cause, for every refusal that would otherwise tell a
     * registered client from an unknown one.
     */
    public const string REFUSED = 'Client authentication failed.';

    /**
     * @param string|null $method the name of the method that refused, null when no method did
     * @param string $description what the client reads back
     * @param bool $malformedRequest "invalid_request" rather than "invalid_client" (RFC 6749 §5.2)
     * @param string|null $detail why it was refused, for the logs alone
     */
    private function __construct(
        public readonly ClientAuthenticationFailureReason $reason,
        public readonly ?string $clientId,
        public readonly ?string $method,
        public readonly string $description,
        public readonly bool $malformedRequest,
        ?string $detail = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($detail ?? $description, 0, $previous);
    }

    /**
     * RFC 6749 §5.2 "invalid_request": the request cannot be read as a client authentication at all, and
     * saying so tells nothing about any client.
     */
    public static function malformedRequest(
        ClientAuthenticationFailureReason $reason,
        ?string $clientId,
        ?string $method,
        string $description,
        ?Throwable $previous = null,
    ): self {
        return new self($reason, $clientId, $method, $description, true, null, $previous);
    }

    /**
     * RFC 6749 §5.2 "invalid_client": the request presents nothing this provider authenticates a client
     * with. Naming no client, it can say what is missing.
     */
    public static function unauthenticated(ClientAuthenticationFailureReason $reason, string $description): self
    {
        return new self($reason, null, null, $description, false);
    }

    /**
     * RFC 6749 §5.2 "invalid_client": the request names a client and does not prove it. Every such
     * refusal reads the same and costs the same.
     */
    public static function refused(
        ClientAuthenticationFailureReason $reason,
        ?string $clientId,
        ?string $method,
        ?string $detail = null,
        ?Throwable $previous = null,
    ): self {
        return new self($reason, $clientId, $method, self::REFUSED, false, $detail, $previous);
    }
}
