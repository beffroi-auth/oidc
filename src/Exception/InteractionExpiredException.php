<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * Shown to the user, never sent to the client.
 */
final class InteractionExpiredException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly string $interactionId,
    ) {
        parent::__construct(sprintf('The interaction "%s" has expired and cannot be resumed.', $interactionId));
    }
}
