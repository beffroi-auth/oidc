<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Identity\Subject;
use function in_array;
use Symfony\Component\Uid\Uuid;

/**
 * What an id_token_hint says once it verified (OIDC Core §3.1.2.1, RP-Initiated Logout §2): the end
 * user it names by "sub", the clients it was issued to by "aud", and the session it was issued in by
 * "sid" (architecture §4.6), when the token carries one. The authorization endpoint reads the subject;
 * the logout endpoint reads all three, so that a request is honoured without asking only for the
 * session it describes.
 */
final readonly class IdTokenHint
{
    /**
     * @param list<string> $audiences the "aud" values; empty when the token carries none the provider can read
     * @param Uuid|null $sessionId the "sid" value, the identifier of the authentication session the token was issued in
     */
    public function __construct(
        public Subject $subject,
        public array $audiences,
        public ?Uuid $sessionId,
    ) {
    }

    /**
     * OIDC Core §2 "aud": the token was issued to this client.
     */
    public function isFor(string $clientId): bool
    {
        return in_array($clientId, $this->audiences, true);
    }
}
