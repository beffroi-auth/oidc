<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * Resumed after it was granted, denied or failed; shown to the user, never sent to the client.
 */
final class InteractionCompletedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly string $interactionId,
    ) {
        parent::__construct(sprintf('The interaction "%s" is completed and cannot be resumed.', $interactionId));
    }
}
