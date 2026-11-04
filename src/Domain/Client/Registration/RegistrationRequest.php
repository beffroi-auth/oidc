<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use SensitiveParameter;

/**
 * RFC 7591 §3.1, RFC 7592 §2.2
 *
 * A body that is no JSON object is refused only when its members are read, so that a caller holding no
 * credential learns nothing about it.
 */
final readonly class RegistrationRequest
{
    /**
     * @param array<string, mixed>|null $members null when the body is no JSON object
     */
    public function __construct(
        private ?array $members = null,
        #[SensitiveParameter]
        public ?string $authorizationHeader = null,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException when the body is no JSON object
     *
     * @return array<string, mixed>
     */
    public function members(): array
    {
        if ($this->members === null) {
            throw new InvalidClientMetadataException(null, null, 'The body of a registration request is a JSON object (RFC 7591 section 3.1).');
        }

        return $this->members;
    }
}
