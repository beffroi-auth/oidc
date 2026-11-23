<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;
use function sprintf;

final class PersonsBudgetSpentException extends RuntimeException implements ExceptionInterface
{
    /**
     * @param int $retryAfter seconds, never zero
     */
    public function __construct(
        public readonly int $retryAfter,
    ) {
        parent::__construct(sprintf('The persons this administrator may read are read; the next ones are served again in %d seconds.', $retryAfter));
    }
}
