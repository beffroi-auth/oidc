<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;

/**
 * An authorization somebody signed in for (architecture §4.5): it descends from a session, so it names a
 * user, it says what that session had proven when it was granted, and the documents that describe the
 * user can be issued from it.
 *
 * Every grant of a browser flow produces one. What an issuer reads here, "sub" resolved for the client,
 * "sid", "auth_time", "acr", "amr" and an ID token, it reads of the authorizations that implement this
 * and of no other: a grant with nobody behind it carries none of it and is asked for none of it.
 */
interface UserAuthorizationInterface extends AuthorizationInterface
{
    public AuthenticationSession $session { get; }

    public User $user { get; }

    /**
     * Only when the grant has one to carry (OIDC Core §3.1.3.7 step 11, §12.2).
     */
    public ?string $nonce { get; }

    /**
     * What the client asked for by name (OIDC Core §5.5), null when it asked for nothing.
     */
    public ?ClaimsRequest $claimsRequest { get; }

    /**
     * What the session had proven at the grant, written in every token descending from it.
     */
    public AuthenticationSnapshot $authentication { get; }
}
