<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Core\Domain\Identity\User;

/**
 * An access token a resource of the provider may honour (architecture §4.6, §4.7), with the user it names.
 */
final readonly class InspectedAccessToken
{
    public function __construct(
        public VerifiedAccessToken $token,
        public User $user,
    ) {
    }
}
