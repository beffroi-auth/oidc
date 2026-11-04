<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\AuthorizationDetails;

use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 9396 §2
 */
interface AuthorizationDetailTypeInterface
{
    /**
     * @return non-empty-string
     */
    public function type(): string;

    /**
     * Members are built in an order of the type's own, so that a consent covers the same detail written in any order.
     *
     * @param array<string, mixed> $members "type" excluded
     *
     * @throws InvalidArgumentException
     */
    public function of(array $members): AuthorizationDetail;
}
