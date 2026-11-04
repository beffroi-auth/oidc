<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * Shown to the user, never sent to the client.
 */
final class InteractionCompletedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly string $interactionId,
    ) {
        parent::__construct(sprintf('The interaction "%s" is completed and cannot be resumed.', $interactionId));
    }
}
