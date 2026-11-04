<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use SensitiveParameter;

final readonly class KeptRegistration
{
    /**
     * @param array<string, mixed> $metadata
     * @param array<string, mixed> $assigned
     * @param array<string, mixed>|null $attested
     * @param string|null $drawnSecret answered once and never kept
     */
    public function __construct(
        public array $metadata,
        public array $assigned,
        public ?array $attested,
        #[SensitiveParameter]
        public ?ClientSecretInterface $secret,
        #[SensitiveParameter]
        public ?string $drawnSecret = null,
    ) {
    }
}
