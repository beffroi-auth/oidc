<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * CIBA Core §13 "invalid_binding_message": the binding message cannot be shown to the user as it was
 * sent, so the request is refused rather than started with a message nobody will be able to match
 * against the one the client shows on its own screen.
 */
final class InvalidBindingMessageException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_binding_message', $description, 400, false, $previous);
    }
}
