<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * An interaction was resumed after it had been granted, denied or failed. Shown to the user by the
 * integration, never sent to the client: the client already received its answer.
 */
final class InteractionCompletedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly string $interactionId,
    ) {
        parent::__construct(sprintf('The interaction "%s" is completed and cannot be resumed.', $interactionId));
    }
}
