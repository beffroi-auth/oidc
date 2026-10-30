<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;

/**
 * An authorization somebody signed in for (architecture §4.5): it descends from a session, so it names a
 * user, it says what that session had proven when it was granted, and the documents that describe the
 * user can be issued from it.
 *
 * Every grant of a browser flow produces one. What an issuer reads here, "sub" resolved for the client,
 * "sid", "auth_time", "acr", "amr", an ID token and the authorization details a user agreed to, it reads of
 * the authorizations that implement this and of no other: a grant with nobody behind it carries none of it
 * and is asked for none of it.
 *
 * The authorization details are here and not on AuthorizationInterface for that reason (RFC 9396 §2): they
 * are what somebody agreed to on a page, so an authorization nobody was asked for carries none, and an
 * issuer that writes them asks for them where they exist.
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
     * What the client asked for by name and may be told (OIDC Core §5.5), null when it asked for nothing.
     */
    public ?ClaimsRequest $claimsRequest { get; }

    /**
     * What the session had proven at the grant, written in every token descending from it.
     */
    public AuthenticationSnapshot $authentication { get; }

    /**
     * What this response carries beyond its scopes ("authorization_details", RFC 9396 §2), null when the
     * request asked for none.
     */
    public ?AuthorizationDetails $authorizationDetails { get; }

    /**
     * What the user agreed to beyond the scopes, which the whole grant stands on, null when they agreed to
     * none. A token request narrows the details of the response and never these (§7).
     */
    public ?AuthorizationDetails $grantedAuthorizationDetails { get; }
}
