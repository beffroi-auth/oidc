<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

interface ClientMetadataSourceInterface
{
    /**
     * @return non-empty-string
     */
    public function source(): string;

    /**
     * @return array<string, mixed> keyed by RFC 7591 §2 member name
     */
    public function members(): array;
}
