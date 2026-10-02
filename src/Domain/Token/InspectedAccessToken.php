<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\User;

/**
 * An access token a resource of the provider may honour (architecture §4.6, §4.7), with the user it names.
 *
 * A token a client holds for itself names no user (RFC 6749 §4.4), and a resource that answers for a user
 * has nothing to answer for it: it is the token itself that says so, and not the name of the grant that
 * issued it.
 */
final readonly class InspectedAccessToken
{
    /**
     * @param User|null $user the user the token names, null when nobody signed in for it
     */
    public function __construct(
        public VerifiedAccessToken $token,
        public ?User $user,
    ) {
    }
}
