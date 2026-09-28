<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use SensitiveParameter;

/**
 * What arrived at the registration endpoint (RFC 7591 §3.1): the JSON object the client sent, member by
 * member as it sent them, and the Authorization header it sent them with.
 *
 * It is what an authorisation reads, and the two modes that read it read different halves of it: the
 * controlled one the header, where the initial access token of §1.2 is presented, and the attested one
 * the body, where the `software_statement` of §2.3 is. Neither is a case of the other, and the request
 * is one thing whichever reads it.
 */
final readonly class RegistrationRequest
{
    /**
     * @param array<string, mixed> $members the JSON object of the request body, as the client wrote it
     * @param string|null $authorizationHeader null when the request carries none
     */
    public function __construct(
        public array $members,
        #[SensitiveParameter]
        public ?string $authorizationHeader = null,
    ) {
    }
}
