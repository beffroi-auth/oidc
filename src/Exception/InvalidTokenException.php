<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 6750 §3.1 "invalid_token": 401 with the challenge.
 *
 * A token refused because it was not issued here reads the same whatever gave it away, a signature, a
 * claim, a store that holds no such record or a shape this provider never draws: the answer tells the
 * caller its token is not one of ours and tells it nothing more (decision 0006). That is one refusal, so
 * it is written once here and never beside each check.
 */
final class InvalidTokenException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_token', $description, 401, false, $previous);
    }

    public static function notIssuedHere(?Throwable $previous = null): self
    {
        return new self('The access token is not an access token issued by this provider.', $previous);
    }

    public static function expired(): self
    {
        return new self('The access token expired.');
    }

    /**
     * RFC 8707 §2: a token asked for a resource is addressed to that resource, and a protected resource
     * of the provider is not it. What the caller holds is a token of this provider, issued to this
     * client, and it opens nothing here all the same.
     */
    public static function addressedElsewhere(): self
    {
        return new self('The access token is addressed to a resource of its own and not to this provider (RFC 8707 section 2).');
    }
}
