<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use Heidi\Oidc\Exception\InvalidClientMetadataException;
use SensitiveParameter;

/**
 * What arrived at a registration or at a client configuration endpoint (RFC 7591 §3.1, RFC 7592 §2.2): the
 * JSON object the client sent, member by member as it sent them, and the Authorization header it sent them
 * with.
 *
 * It is what an authorisation reads, and the two modes that read it read different halves of it: the
 * controlled one the header, where the initial access token of §1.2 is presented, and the attested one the
 * body, where the `software_statement` of §2.3 is. Neither is a case of the other, and the request is one
 * thing whichever reads it.
 *
 * **A body that is no JSON object is a request that carries no members**, and saying so is the request's
 * own business rather than the caller's: what refuses first is then decided where the other refusals are
 * ordered, so a caller holding no credential is told that and nothing about the body it sent.
 */
final readonly class RegistrationRequest
{
    /**
     * @param array<string, mixed>|null $members the JSON object of the request body, as the client wrote it; null when the body was no JSON object at all
     * @param string|null $authorizationHeader null when the request carries none
     */
    public function __construct(
        private ?array $members = null,
        #[SensitiveParameter]
        public ?string $authorizationHeader = null,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException when the body was no JSON object (RFC 7591 §3.1)
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
