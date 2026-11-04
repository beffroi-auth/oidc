<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Authorization\RequestObject;

final readonly class ResolvedRequestObject
{
    /**
     * @param array<string, string|list<string>> $parameters
     */
    public function __construct(
        public RequestObject $object,
        public array $parameters,
    ) {
    }
}
