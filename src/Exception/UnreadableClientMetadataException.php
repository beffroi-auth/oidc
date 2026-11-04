<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §2, §3.2.2
 */
abstract class UnreadableClientMetadataException extends InvalidArgumentException
{
    /**
     * @param non-empty-string $error
     * @param string|null $member null for a rule between several members
     * @param string|null $source where the value came from (ClientMetadataSourceInterface), null when none carried it
     */
    public function __construct(
        public readonly string $error,
        public readonly ?string $member,
        public readonly ?string $source,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
