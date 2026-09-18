<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Identity\Subject;
use function in_array;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified id_token_hint says (OIDC Core §3.1.2.1, RP-Initiated Logout §2): "sub", "aud" and "sid".
 */
final readonly class IdTokenHint
{
    /**
     * @param list<string> $audiences
     */
    public function __construct(
        public Subject $subject,
        public array $audiences,
        public ?Uuid $sessionId,
    ) {
    }

    public function isFor(string $clientId): bool
    {
        return in_array($clientId, $this->audiences, true);
    }
}
