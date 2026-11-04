<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\OAuth2Exception;
use RuntimeException;
use Throwable;

final class ClientAuthenticationFailure extends RuntimeException
{
    /**
     * One description whatever the cause, so that a refusal never tells a registered client from an unknown one.
     */
    public const string REFUSED = 'Client authentication failed.';

    /**
     * @param string|null $detail for the logs alone
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
        OAuth2Exception::assertDescription($description);
        parent::__construct($detail ?? $description, 0, $previous);
    }

    /**
     * RFC 6749 §5.2 "invalid_request"
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
     * RFC 6749 §5.2 "invalid_client"
     */
    public static function unauthenticated(ClientAuthenticationFailureReason $reason, string $description): self
    {
        return new self($reason, null, null, $description, false);
    }

    /**
     * RFC 6749 §5.2 "invalid_client"
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
