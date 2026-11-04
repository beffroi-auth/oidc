<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * RFC 6749 §3.1.1
 *
 * Code only: decision 0006 admits no implicit and no hybrid flow.
 */
final readonly class ResponseTypeNames
{
    public const string CODE = 'code';
}
