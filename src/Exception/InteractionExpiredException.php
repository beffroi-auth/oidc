<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException;
use function sprintf;

/**
 * An interaction was resumed after its lifetime. Shown to the user by the integration, who starts again
 * from the client; nothing is sent to the redirect URI on the client's behalf.
 */
final class InteractionExpiredException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly string $interactionId,
    ) {
        parent::__construct(sprintf('The interaction "%s" has expired and cannot be resumed.', $interactionId));
    }
}
