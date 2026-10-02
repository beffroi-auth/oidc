<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Exchange\Actor;

/**
 * An authorization whose subject is named by what the client presented, and not by a session this provider
 * opened (architecture §4.5): a token exchange names the subject of the token it spends (RFC 8693 §2.2.1),
 * an assertion grant the subject its issuer vouched for (RFC 7523 §2.1).
 *
 * The issuers read the "sub" and the sign-in here and derive neither: there is nobody to resolve a subject
 * for, the subject having been resolved when the token this one descends from was issued or having been
 * vouched for by somebody else; and there is no session to name in a "sid" beyond the one that token
 * already named, which is carried unchanged so that the provider keeps asking of the new token what it
 * asked of the old one.
 */
interface NamesItsSubjectInterface extends AuthorizationInterface
{
    /**
     * The "sub" of the tokens of this response (RFC 9068 §2.2), as whatever named it named it.
     */
    public Subject $subject { get; }

    /**
     * The sign-in the tokens of this response descend from (RFC 9068 §2.2.1), null when they descend from
     * none: a token of a client acting for itself was exchanged, or an issuer vouched for a subject this
     * provider never signed in.
     */
    public ?TokenSignIn $signIn { get; }

    /**
     * Who acts for the subject (RFC 8693 §4.1), null when nobody does and the response is the subject
     * itself (§1.3).
     */
    public ?Actor $actor { get; }
}
