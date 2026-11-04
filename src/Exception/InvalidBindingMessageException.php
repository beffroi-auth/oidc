<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * CIBA Core §13
 */
final class InvalidBindingMessageException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_binding_message', $description, 400, false, $previous);
    }
}
