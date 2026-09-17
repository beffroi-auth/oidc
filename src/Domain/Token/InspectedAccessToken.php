<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Core\Domain\Identity\User;

/**
 * An access token a resource of the provider may honour (architecture §4.6, §4.7): verified in its shape,
 * its grant alive, and the user it names still served, found once and handed over, because the resource
 * is about to answer for that user.
 */
final readonly class InspectedAccessToken
{
    public function __construct(
        public VerifiedAccessToken $token,
        public User $user,
    ) {
    }
}
